package tw.bonds.backuptw.wallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/**
 * An Android Keystore-resident P-256 key: one key per card, named by a
 * caller-chosen alias, matching iOS's `HolderKeyring` (one `DeviceKey`
 * per collected credential, found again by its public key or its own
 * tag - never `DeviceKey.defaultTag`). The private key material never
 * leaves the keystore; every operation here goes through the JCA
 * `Signature`/`KeyPairGenerator` SPI rather than touching key bytes
 * directly.
 */
class KeystoreHolderKey private constructor(
    private val alias: String,
) : SigningKeyHandle {
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun publicKeyX963(): ByteArray {
        val certificate = keyStore.getCertificate(alias) as X509Certificate
        val publicKey = certificate.publicKey as ECPublicKey
        return EcdsaCodec.x963(publicKey.w.affineX, publicKey.w.affineY)
    }

    override fun signRaw(message: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(alias, null)
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey as java.security.PrivateKey)
        signature.update(message)
        return EcdsaCodec.derToRaw(signature.sign())
    }

    companion object {
        /** Generates a fresh key under `alias`, replacing one if it exists. */
        fun generate(alias: String): KeystoreHolderKey {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
            return KeystoreHolderKey(alias)
        }

        /** Loads a previously generated key, or `null` if `alias` doesn't exist. */
        fun load(alias: String): KeystoreHolderKey? {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            return if (keyStore.containsAlias(alias)) KeystoreHolderKey(alias) else null
        }

        fun delete(alias: String) {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }
}
