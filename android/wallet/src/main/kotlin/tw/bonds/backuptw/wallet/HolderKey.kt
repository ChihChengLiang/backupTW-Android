package tw.bonds.backuptw.wallet

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * A software-generated, in-memory P-256 key - ephemeral, not the real
 * design. See [KeystoreHolderKey] for the Android Keystore-backed
 * variant a real card's key should use; both implement [SigningKeyHandle]
 * identically, so call sites don't care which one they're holding.
 */
class HolderKey private constructor(
    private val privateKey: ECPrivateKey,
    private val publicKey: ECPublicKey,
) : SigningKeyHandle {
    override fun publicKeyX963(): ByteArray = EcdsaCodec.x963(publicKey.w.affineX, publicKey.w.affineY)

    override fun signRaw(message: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(message)
        return EcdsaCodec.derToRaw(signature.sign())
    }

    companion object {
        fun generate(): HolderKey {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val pair = generator.generateKeyPair()
            return HolderKey(pair.private as ECPrivateKey, pair.public as ECPublicKey)
        }
    }
}
