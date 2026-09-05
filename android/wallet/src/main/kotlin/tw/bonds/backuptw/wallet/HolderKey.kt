package tw.bonds.backuptw.wallet

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * A software-generated, in-memory P-256 key - ephemeral, not the real
 * design. Same framing as [uniffi.backuptw_core.generateEphemeralWalletIdentity]:
 * the real design is Android Keystore-backed generation behind a
 * trait/callback boundary `core/` doesn't have yet (Phase 3). What this
 * class gets right on purpose, so it isn't wasted work: the X9.63 public
 * key encoding and the DER-to-raw ECDSA signature conversion are exactly
 * what real Keystore signing will need too - `Signature.getInstance(...)`
 * against a Keystore-resident key produces the same DER shape a
 * software key does.
 */
class HolderKey private constructor(
    private val privateKey: ECPrivateKey,
    private val publicKey: ECPublicKey,
) {
    /** `0x04 || X || Y`, each coordinate left-zero-padded to 32 bytes. */
    fun publicKeyX963(): ByteArray {
        val x = unsignedBytes32(publicKey.w.affineX)
        val y = unsignedBytes32(publicKey.w.affineY)
        return byteArrayOf(0x04) + x + y
    }

    /**
     * ECDSA-SHA256 over `message`, as a fixed 64-byte `r ‖ s` pair (the
     * JOSE/production convention this whole port uses) rather than the
     * DER `SEQUENCE { INTEGER r, INTEGER s }` the JCA `Signature` API
     * returns.
     */
    fun signRaw(message: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(message)
        return derToRaw(signature.sign())
    }

    companion object {
        fun generate(): HolderKey {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"))
            val pair = generator.generateKeyPair()
            return HolderKey(pair.private as ECPrivateKey, pair.public as ECPublicKey)
        }

        private fun unsignedBytes32(value: BigInteger): ByteArray {
            val bytes = value.toByteArray() // big-endian, two's-complement; may carry a leading 0x00 sign byte
            val trimmed = if (bytes.size > 32) bytes.copyOfRange(bytes.size - 32, bytes.size) else bytes
            val padded = ByteArray(32)
            System.arraycopy(trimmed, 0, padded, 32 - trimmed.size, trimmed.size)
            return padded
        }

        /** Decodes a DER ECDSA signature and re-encodes `r`/`s` as fixed 32-byte values each. */
        private fun derToRaw(der: ByteArray): ByteArray {
            // SEQUENCE(0x30, len) INTEGER(0x02, rLen, rBytes) INTEGER(0x02, sLen, sBytes)
            require(der.isNotEmpty() && der[0] == 0x30.toByte()) { "not a DER ECDSA signature" }
            var offset = 2
            if ((der[1].toInt() and 0x80) != 0) {
                // Long-form length: skip the extra length-of-length bytes.
                offset += der[1].toInt() and 0x7F
            }
            require(der[offset] == 0x02.toByte()) { "expected INTEGER for r" }
            val rLen = der[offset + 1].toInt()
            val r = der.copyOfRange(offset + 2, offset + 2 + rLen)
            offset += 2 + rLen
            require(der[offset] == 0x02.toByte()) { "expected INTEGER for s" }
            val sLen = der[offset + 1].toInt()
            val s = der.copyOfRange(offset + 2, offset + 2 + sLen)

            return unsignedBytes32(BigInteger(r)) + unsignedBytes32(BigInteger(s))
        }
    }
}
