package dev.peage.reactnative

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.KeyStoreException
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableMap
import com.facebook.react.module.annotations.ReactModule
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONArray
import org.json.JSONObject

@ReactModule(name = PeageAttestModule.NAME)
class PeageAttestModule(private val reactContext: ReactApplicationContext) :
    NativePeageAttestSpec(reactContext) {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val preferences =
        reactContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val integrityManager = IntegrityManagerFactory.create(reactContext)

    private val pendingAliases = ConcurrentHashMap<String, String>()

    override fun getName(): String = NAME

    override fun isSupported(promise: Promise) {
        val hasPlayStore = try {
            reactContext.packageManager.getPackageInfo(PLAY_STORE_PACKAGE, 0)
            true
        } catch (error: PackageManager.NameNotFoundException) {
            false
        }
        promise.resolve(hasPlayStore)
    }

    override fun generateKey(clientDataHash: String, scope: String, promise: Promise) {
        settle(promise, "E_GENERATE_KEY") {
            deleteScopeKeysExcept(scope, registeredAlias(scope))
            val alias = aliasPrefixOf(scope) + UUID.randomUUID()
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(base64urlDecode(clientDataHash))
                .build()
            val generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            generator.initialize(spec)
            val keyId = keyIdOf(generator.generateKeyPair().public as ECPublicKey)
            pendingAliases[keyId] = alias
            keyId
        }
    }

    override fun markAttested(keyId: String, scope: String, promise: Promise) {
        settle(promise, "E_PERSIST_KEY_ID") {
            val alias = aliasFor(keyId)
            val editor = preferences.edit()
            registeredKeyId(scope)?.let { editor.remove(aliasPreference(it)) }
            editor
                .putString(keyIdPreference(scope), keyId)
                .putString(aliasPreference(keyId), alias)
            check(editor.commit()) { "Could not save the keyId" }
            deleteScopeKeysExcept(scope, alias)
            null
        }
    }

    // SharedPreferences survive a backup or device transfer; Keystore keys don't.
    override fun getKeyId(scope: String, promise: Promise) {
        settle(promise, "E_READ_KEY_ID") {
            val keyId = registeredKeyId(scope)
            val alias = registeredAlias(scope)
            if (keyId != null && alias != null && keyStore.containsAlias(alias)) {
                keyId
            } else {
                forgetRegisteredKey(scope)
                null
            }
        }
    }

    override fun clearKeyId(scope: String, promise: Promise) {
        settle(promise, "E_CLEAR_KEY") {
            registeredAlias(scope)?.let(keyStore::deleteEntry)
            forgetRegisteredKey(scope)
            null
        }
    }

    override fun attestKey(keyId: String, clientDataHash: String, promise: Promise) {
        try {
            val certificateChain = keyStore.getCertificateChain(aliasFor(keyId))
            val publicKeySpki = certificateChain.first().publicKey.encoded
            val challengeHash = base64urlDecode(clientDataHash)
            // Padded URL-safe base64, as in Google's own samples.
            val nonce = Base64.encodeToString(
                sha256(challengeHash + publicKeySpki),
                Base64.URL_SAFE or Base64.NO_WRAP,
            )
            val request = IntegrityTokenRequest.builder().setNonce(nonce).build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    val encodedChain = certificateChain.map {
                        Base64.encodeToString(it.encoded, Base64.NO_WRAP)
                    }
                    val proof = JSONObject()
                        .put("integrityToken", response.token())
                        .put("certificateChain", JSONArray(encodedChain))
                    promise.resolve(base64urlEncode(proof.toString().toByteArray(Charsets.UTF_8)))
                }
                .addOnFailureListener { error ->
                    promise.reject(
                        "E_INTEGRITY_TOKEN",
                        error.message,
                        error,
                        integrityErrorInfo(error),
                    )
                }
        } catch (error: Exception) {
            promise.reject(errorCode(error, "E_ATTEST_KEY"), error.message, error)
        }
    }

    override fun generateAssertion(keyId: String, clientDataHash: String, promise: Promise) {
        settle(promise, "E_GENERATE_ASSERTION") {
            val signer = Signature.getInstance("SHA256withECDSA")
            val entry = keyStore.getEntry(aliasFor(keyId), null) as? KeyStore.PrivateKeyEntry
                ?: throw MissingKeyException(keyId)
            signer.initSign(entry.privateKey)
            signer.update(base64urlDecode(clientDataHash))
            base64urlEncode(signer.sign())
        }
    }

    override fun sha256(data: String, promise: Promise) {
        settle(promise, "E_SHA256") { base64urlEncode(sha256(base64urlDecode(data))) }
    }

    private fun aliasFor(keyId: String): String {
        val alias = pendingAliases[keyId] ?: preferences.getString(aliasPreference(keyId), null)
        if (alias == null || !keyStore.containsAlias(alias)) {
            throw MissingKeyException(keyId)
        }
        return alias
    }

    private fun registeredKeyId(scope: String): String? =
        preferences.getString(keyIdPreference(scope), null)

    private fun registeredAlias(scope: String): String? =
        registeredKeyId(scope)?.let { preferences.getString(aliasPreference(it), null) }

    private fun forgetRegisteredKey(scope: String) {
        val editor = preferences.edit().remove(keyIdPreference(scope))
        registeredKeyId(scope)?.let { editor.remove(aliasPreference(it)) }
        check(editor.commit()) { "Could not forget the keyId" }
    }

    private fun deleteScopeKeysExcept(scope: String, keptAlias: String?) {
        val prefix = aliasPrefixOf(scope)
        pendingAliases.values.removeIf { it.startsWith(prefix) }
        keyStore.aliases().toList()
            .filter { it.startsWith(prefix) && it != keptAlias }
            .forEach(keyStore::deleteEntry)
    }

    private class MissingKeyException(keyId: String) : Exception("No Keystore key for keyId $keyId")

    companion object {
        const val NAME = "PeageAttest"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PLAY_STORE_PACKAGE = "com.android.vending"
        private const val KEY_ALIAS_PREFIX = "dev.peage.key."
        private const val PREFERENCES_NAME = "dev.peage.react-native"
        private const val P256_COORDINATE_BYTES = 32

        /** Hashed: a scope can be any string, an alias can't. */
        private fun aliasPrefixOf(scope: String): String =
            KEY_ALIAS_PREFIX + base64urlEncode(sha256(scope.toByteArray(Charsets.UTF_8))) + "."

        private fun keyIdPreference(scope: String): String = "keyId:$scope"

        private fun aliasPreference(keyId: String): String = "alias:$keyId"

        /** base64 SHA-256 of the uncompressed point (0x04 ‖ x ‖ y), as Apple defines keyId. */
        fun keyIdOf(publicKey: ECPublicKey): String {
            val point = byteArrayOf(0x04) +
                unsignedBytes(publicKey.w.affineX, P256_COORDINATE_BYTES) +
                unsignedBytes(publicKey.w.affineY, P256_COORDINATE_BYTES)
            return Base64.encodeToString(sha256(point), Base64.NO_WRAP)
        }

        /** Big-endian, left-padded to `length`, without BigInteger's sign byte. */
        private fun unsignedBytes(value: BigInteger, length: Int): ByteArray {
            val signed = value.toByteArray()
            val unsigned = if (signed.size > length) {
                signed.copyOfRange(signed.size - length, signed.size)
            } else {
                signed
            }
            return ByteArray(length - unsigned.size) + unsigned
        }

        private fun sha256(input: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(input)

        private fun base64urlEncode(bytes: ByteArray): String =
            Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        private fun base64urlDecode(value: String): ByteArray =
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP)

        private fun errorCode(error: Exception, fallback: String): String =
            if (isInvalidKey(error)) "E_INVALID_KEY" else fallback

        private fun isInvalidKey(error: Exception): Boolean = when (error) {
            is MissingKeyException,
            is UnrecoverableKeyException,
            -> true
            is InvalidKeyException -> !isTransientKeystoreFailure(error)
            else -> false
        }

        private fun isTransientKeystoreFailure(error: InvalidKeyException): Boolean {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                return false
            }
            val cause = error.cause
            return cause is KeyStoreException && cause.isTransientFailure
        }

        private fun integrityErrorInfo(error: Exception): WritableMap? {
            if (error !is IntegrityServiceException) {
                return null
            }
            return Arguments.createMap().apply { putInt("integrityErrorCode", error.errorCode) }
        }

        private inline fun settle(promise: Promise, fallbackCode: String, block: () -> Any?) {
            try {
                promise.resolve(block())
            } catch (error: Exception) {
                promise.reject(errorCode(error, fallbackCode), error.message, error)
            }
        }
    }
}
