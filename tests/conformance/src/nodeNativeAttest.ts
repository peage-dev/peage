import type { NativeAttest } from '@peage/react-native/testing'

import { concatBytes, fromBase64url, toBase64url } from '@peage/protocol'
import {
  encodePlayIntegrityToken,
  issueKeyAttestationChain,
  type KeyAttestationTestRoot,
  keyIdFor,
  playIntegrityProof,
  playIntegrityVerdict,
  type PlayIntegrityTestKeys,
  signAppAttestClientDataHash,
  signPlayIntegrityClientDataHash,
} from '@peage/tests'
import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto'

type NodeNativeAttest = {
  native: NativeAttest
  publicKeyFor: (keyId: string) => KeyObject | undefined
}

type PlatformBehaviour = Pick<NativeAttest, 'attestKey' | 'generateAssertion'>

type DeviceKey = {
  privateKey: KeyObject
  publicKey: KeyObject
  /** What `generateKey` was given: SHA-256 of the challenge. */
  attestationChallenge: Uint8Array
}

function sha256(input: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest())
}

function createNodeNative(
  buildPlatform: (deviceKeyFor: (keyId: string) => DeviceKey) => PlatformBehaviour,
): NodeNativeAttest {
  const deviceKeys = new Map<string, DeviceKey>()
  const persistedKeyIds = new Map<string, string>()

  const platform = buildPlatform((keyId) => {
    const deviceKey = deviceKeys.get(keyId)
    if (!deviceKey) {
      throw new Error(`node native faker has no key for keyId ${keyId}`)
    }
    return deviceKey
  })

  const native: NativeAttest = {
    async isSupported() {
      return true
    },
    async generateKey(clientDataHash) {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      const keyId = keyIdFor(publicKey)
      const attestationChallenge = fromBase64url(clientDataHash)
      deviceKeys.set(keyId, { privateKey, publicKey, attestationChallenge })
      return keyId
    },
    async markAttested(keyId, scope) {
      persistedKeyIds.set(scope, keyId)
    },
    async getKeyId(scope) {
      return persistedKeyIds.get(scope) ?? null
    },
    async clearKeyId(scope) {
      persistedKeyIds.delete(scope)
    },
    async sha256(data) {
      return toBase64url(sha256(fromBase64url(data)))
    },
    ...platform,
  }

  return { native, publicKeyFor: (keyId) => deviceKeys.get(keyId)?.publicKey }
}

/**
 * Stands in for the iOS module. `attestKey` is unsupported: Apple's
 * certificate chain can't be forged, so tests seed the store with the key.
 */
export function createNodeAppAttest(options: {
  appId: string
  /** Trailing authenticatorData bytes, e.g. the iOS 27 extensions map. */
  extensions?: Uint8Array
}): NodeNativeAttest {
  return createNodeNative((deviceKeyFor) => ({
    async attestKey() {
      throw new Error('node attest faker cannot forge an Apple attestation')
    },
    async generateAssertion(keyId, clientDataHash) {
      const { assertion } = signAppAttestClientDataHash({
        appId: options.appId,
        clientDataHash: fromBase64url(clientDataHash),
        extensions: options.extensions,
        privateKey: deviceKeyFor(keyId).privateKey,
      })
      return toBase64url(assertion)
    },
  }))
}

/** Stands in for the Android module, with test keys and a test attestation root. */
export function createNodePlayIntegrityAttest(options: {
  packageName: string
  keys: PlayIntegrityTestKeys
  keyAttestationRoot: KeyAttestationTestRoot
  /** Override verdict fields, e.g. a device that fails integrity. */
  verdict?: Partial<Parameters<typeof playIntegrityVerdict>[0]>
}): NodeNativeAttest {
  return createNodeNative((deviceKeyFor) => ({
    async attestKey(keyId, clientDataHash) {
      const { publicKey, attestationChallenge } = deviceKeyFor(keyId)
      const spki = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }))
      const nonce = toBase64url(sha256(concatBytes(fromBase64url(clientDataHash), spki)))
      const verdict = playIntegrityVerdict({
        packageName: options.packageName,
        nonce,
        ...options.verdict,
      })
      const certificateChain = issueKeyAttestationChain({
        root: options.keyAttestationRoot,
        publicKey,
        keyDescription: { attestationChallenge, packageName: options.packageName },
      })
      const token = encodePlayIntegrityToken(verdict, options.keys)
      return toBase64url(playIntegrityProof(token, certificateChain))
    },
    async generateAssertion(keyId, clientDataHash) {
      return toBase64url(
        signPlayIntegrityClientDataHash(
          deviceKeyFor(keyId).privateKey,
          fromBase64url(clientDataHash),
        ),
      )
    },
  }))
}
