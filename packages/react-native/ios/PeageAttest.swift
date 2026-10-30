import CryptoKit
import DeviceCheck
import Foundation
import React
import Security

/// The App Attest implementation; `PeageAttest.mm` exposes it as the Turbo Module.
@objc(PeageAttestImpl)
public final class PeageAttestImpl: NSObject {
  private static let keychainService = "dev.peage.react-native"
  private static let keychainAccountPrefix = "appAttestKeyId."

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
    do {
      try Keychain.write(keyId, service: Self.keychainService, account: Self.keychainAccount(scope))
      resolve(NSNull())
    } catch {
      reject("E_KEYCHAIN_WRITE", error.localizedDescription, error)
    }
  }

  @objc public func getKeyId(_ scope: String,
                             resolve: @escaping RCTPromiseResolveBlock,
                             reject: @escaping RCTPromiseRejectBlock) {
    do {
      // String? bridges to JS null when nil.
      let keyId = try Keychain.read(service: Self.keychainService, account: Self.keychainAccount(scope))
      resolve(keyId as Any)
    } catch {
      reject("E_KEYCHAIN_READ", error.localizedDescription, error)
    }
  }

  @objc public func clearKeyId(_ scope: String,
                               resolve: @escaping RCTPromiseResolveBlock,
                               reject: @escaping RCTPromiseRejectBlock) {
    do {
      try Keychain.delete(service: Self.keychainService, account: Self.keychainAccount(scope))
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

  private static func keychainAccount(_ scope: String) -> String {
    keychainAccountPrefix + scope
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
  static func write(_ value: String, service: String, account: String) throws {
    let data = Data(value.utf8)
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    let updateStatus = SecItemUpdate(
      query as CFDictionary, [kSecValueData as String: data] as CFDictionary
    )
    if updateStatus == errSecSuccess { return }
    if updateStatus != errSecItemNotFound { throw KeychainError.osStatus(updateStatus) }

    var addQuery = query
    addQuery[kSecValueData as String] = data
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    guard addStatus == errSecSuccess else { throw KeychainError.osStatus(addStatus) }
  }

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
