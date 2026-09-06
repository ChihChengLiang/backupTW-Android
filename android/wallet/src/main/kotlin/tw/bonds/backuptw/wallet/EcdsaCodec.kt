package tw.bonds.backuptw.wallet

import java.math.BigInteger

/**
 * ECDSA/X9.63 byte-shape conversions shared by every P-256 key this app
 * signs with, software ([HolderKey]) or Android Keystore-backed
 * ([KeystoreHolderKey]) - both go through the same JCA `Signature` API
 * and produce the same DER shape, so the conversion to the raw `r ‖ s`
 * JOSE/production convention this whole port uses is identical either
 * way.
 */
internal object EcdsaCodec {
    /** `0x04 || X || Y`, each coordinate left-zero-padded to 32 bytes. */
    fun x963(x: BigInteger, y: BigInteger): ByteArray = byteArrayOf(0x04) + unsignedBytes32(x) + unsignedBytes32(y)

    fun unsignedBytes32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray() // big-endian, two's-complement; may carry a leading 0x00 sign byte
        val trimmed = if (bytes.size > 32) bytes.copyOfRange(bytes.size - 32, bytes.size) else bytes
        val padded = ByteArray(32)
        System.arraycopy(trimmed, 0, padded, 32 - trimmed.size, trimmed.size)
        return padded
    }

    /** Decodes a DER ECDSA signature and re-encodes `r`/`s` as fixed 32-byte values each. */
    fun derToRaw(der: ByteArray): ByteArray {
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

/** A P-256 signing key this app can hold - software ([HolderKey]) or Keystore-backed ([KeystoreHolderKey]). */
interface SigningKeyHandle {
    /** `0x04 || X || Y`, X9.63 uncompressed, 65 bytes. */
    fun publicKeyX963(): ByteArray

    /** ECDSA-SHA256 over `message`, as a fixed 64-byte `r ‖ s` pair. */
    fun signRaw(message: ByteArray): ByteArray
}
