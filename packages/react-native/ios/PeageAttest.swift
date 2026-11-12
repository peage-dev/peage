import CryptoKit
import DeviceCheck
import Foundation
import React
import Security

/// The App Attest implementation; `PeageAttest.mm` exposes it as the Turbo Module.
@objc(PeageAttestImpl)
public final class PeageAttestImpl: NSObject {
  /// UserDefaults are deleted with the app, like its App Attest keys; Keychain items aren't. A
  /// backup restored on another device brings the keyId back without its key; the client then
  /// registers a new one.
  private static let keyIdDefaultsPrefix = "dev.peage.react-native.appAttestKeyId."
  /// Where 0.4.1 and earlier stored keyIds.
  private static let legacyKeychainService = "dev.peage.react-native"
  private static let legacyKeychainAccountPrefix = "appAttestKeyId."

  @objc public func isSupported(_ resolve: @escaping RCTPromiseResolveBlock,
                                reject: @escaping RCTPromiseRejectBlock) {
    resolve(DCAppAttestService.shared.isSupported)
  }

  @objc public func generateKey(_ resolve: @escaping RCTPromiseResolveBlock,
                                reject: @escaping RCTPromiseRejectBlock) {
    Task {
      do {
        resolve(try await DCAppAttestService.shared.generateKey())
      } catch {
        reject(Self.errorCode(for: error, fallback: "E_GENERATE_KEY"), error.localizedDescription, error)
      }
    }
  }

  @objc public func markAttested(_ keyId: String,
                                 scope: String,
                                 resolve: @escaping RCTPromiseResolveBlock,
                                 reject: @escaping RCTPromiseRejectBlock) {
    UserDefaults.standard.set(keyId, forKey: Self.keyIdDefaultsKey(scope))
    resolve(NSNull())
  }

  @objc public func getKeyId(_ scope: String,
                             resolve: @escaping RCTPromiseResolveBlock,
                             reject: @escaping RCTPromiseRejectBlock) {
    do {
      // String? bridges to JS null when nil.
      resolve(try Self.storedKeyId(scope) as Any)
    } catch {
      reject("E_KEYCHAIN_READ", error.localizedDescription, error)
    }
  }

  @objc public func clearKeyId(_ scope: String,
                               resolve: @escaping RCTPromiseResolveBlock,
                               reject: @escaping RCTPromiseRejectBlock) {
    do {
      UserDefaults.standard.removeObject(forKey: Self.keyIdDefaultsKey(scope))
      try Keychain.delete(service: Self.legacyKeychainService, account: Self.legacyKeychainAccount(scope))
      resolve(NSNull())
    } catch {
      reject("E_KEYCHAIN_DELETE", error.localizedDescription, error)
    }
  }

  @objc public func attestKey(_ keyId: String,
                              clientDataHash: String,
                              resolve: @escaping RCTPromiseResolveBlock,
                              reject: @escaping RCTPromiseRejectBlock) {
    guard let hash = Data(base64URLEncoded: clientDataHash) else {
      reject("E_BAD_INPUT", "clientDataHash is not valid base64url", nil)
      return
    }
    Task {
      do {
        let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: hash)
        resolve(attestation.base64URLEncodedString())
      } catch {
        reject(Self.errorCode(for: error, fallback: "E_ATTEST"), error.localizedDescription, error)
      }
    }
  }

  @objc public func generateAssertion(_ keyId: String,
                                      clientDataHash: String,
                                      resolve: @escaping RCTPromiseResolveBlock,
                                      reject: @escaping RCTPromiseRejectBlock) {
    guard let hash = Data(base64URLEncoded: clientDataHash) else {
      reject("E_BAD_INPUT", "clientDataHash is not valid base64url", nil)
      return
    }
    Task {
      do {
        let assertion = try await DCAppAttestService.shared.generateAssertion(
          keyId, clientDataHash: hash
        )
        resolve(assertion.base64URLEncodedString())
      } catch {
        reject(Self.errorCode(for: error, fallback: "E_ASSERT"), error.localizedDescription, error)
      }
    }
  }

  @objc public func sha256(_ data: String,
                           resolve: @escaping RCTPromiseResolveBlock,
                           reject: @escaping RCTPromiseRejectBlock) {
    guard let bytes = Data(base64URLEncoded: data) else {
      reject("E_BAD_INPUT", "data is not valid base64url", nil)
      return
    }
    resolve(Data(SHA256.hash(data: bytes)).base64URLEncodedString())
  }

  private static func keyIdDefaultsKey(_ scope: String) -> String {
    keyIdDefaultsPrefix + scope
  }

  private static func legacyKeychainAccount(_ scope: String) -> String {
    legacyKeychainAccountPrefix + scope
  }

  /// Moves a keyId from where 0.4.1 and earlier stored it, so an app update keeps its key. After a
  /// reinstall that keyId has no key left; the client then registers a new one.
  private static func storedKeyId(_ scope: String) throws -> String? {
    if let keyId = UserDefaults.standard.string(forKey: keyIdDefaultsKey(scope)) {
      return keyId
    }
    let account = legacyKeychainAccount(scope)
    guard let legacyKeyId = try Keychain.read(service: legacyKeychainService, account: account) else {
      return nil
    }
    UserDefaults.standard.set(legacyKeyId, forKey: keyIdDefaultsKey(scope))
    // UserDefaults is read first from now on, so an item left behind is never read again.
    try? Keychain.delete(service: legacyKeychainService, account: account)
    return legacyKeyId
  }

  private static func errorCode(for error: Error, fallback: String) -> String {
    guard let appAttestError = error as? DCError else { return fallback }
    switch appAttestError.code {
    case .invalidKey: return "E_INVALID_KEY"
    case .featureUnsupported: return "E_UNSUPPORTED"
    case .serverUnavailable: return "E_SERVER_UNAVAILABLE"
    case .invalidInput: return "E_INVALID_INPUT"
    default: return fallback
    }
  }
}

// MARK: - Keychain

private enum Keychain {
  static func read(service: String, account: String) throws -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw KeychainError.osStatus(status) }
    guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
      throw KeychainError.dataInvalid
    }
    return value
  }

  static func delete(service: String, account: String) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      throw KeychainError.osStatus(status)
    }
  }
}

private enum KeychainError: LocalizedError {
  case osStatus(OSStatus)
  case dataInvalid

  var errorDescription: String? {
    switch self {
    case .osStatus(let status): return "Keychain error: \(status)"
    case .dataInvalid: return "Keychain stored data is not UTF-8"
    }
  }
}

// MARK: - base64url

private extension Data {
  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  init?(base64URLEncoded input: String) {
    var base64 = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
    self.init(base64Encoded: base64)
  }
}
