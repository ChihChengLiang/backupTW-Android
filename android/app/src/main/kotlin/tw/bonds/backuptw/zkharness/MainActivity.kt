package tw.bonds.backuptw.zkharness

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.createAgePrepareInput
import uniffi.mopro.createAgeShowInput
import uniffi.mopro.generateSharedBlinds
import uniffi.mopro.proveJwt
import uniffi.mopro.proveShow
import uniffi.mopro.reblindJwt
import uniffi.mopro.reblindShow
import uniffi.mopro.setupJwtKeys
import uniffi.mopro.setupShowKeys
import uniffi.mopro.verifyAgePresentation

private const val TAG = "ZkHarness"

/**
 * Replays the same fixed test vector as backupTW-iOS's
 * Native/OpenACAge/age_assets.rs release gate, through the generated
 * Kotlin/UniFFI bindings instead of calling the Rust library directly.
 * Field VALUES match age_assets.rs; the JSON *byte layout* does not need
 * to (createAgePrepareInput parses arbitrary conformant SD-JWTs, it isn't
 * a byte-offset check against this one vector) - see android/README.md.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Internal storage (filesDir), not external: files pushed into
        // Android/data/<pkg> via plain `adb shell mkdir`/`push` aren't
        // visible to the app's own process under scoped storage's FUSE
        // isolation (they're owned by "shell", not recognized as part of
        // the app's storage domain) - see android/README.md.
        val documentsPath = File(filesDir, "circom").absolutePath
        Thread { runCheck(documentsPath) }.start()
    }

    private fun runCheck(documentsPath: String) {
        try {
            val result = runFixedVector(documentsPath)
            Log.i(TAG, "RESULT: PASS ($result)")
        } catch (t: Throwable) {
            Log.e(TAG, "RESULT: FAIL: ${t.javaClass.simpleName}: ${t.message}", t)
        }
    }

    private fun runFixedVector(documentsPath: String): String {
        val jwtR1cs = File(documentsPath, "build/jwt/jwt_js/jwt.r1cs")
        val showR1cs = File(documentsPath, "build/show/show_js/show.r1cs")
        Log.i(TAG, "documentsPath=$documentsPath")
        Log.i(TAG, "jwtR1cs exists=${jwtR1cs.exists()} len=${jwtR1cs.length()} canRead=${jwtR1cs.canRead()}")
        Log.i(TAG, "showR1cs exists=${showR1cs.exists()} len=${showR1cs.length()} canRead=${showR1cs.canRead()}")
        val jwtSetup = setupJwtKeys(documentsPath)
        val showSetup = setupShowKeys(documentsPath)
        Log.i(TAG, "key setup: jwt=$jwtSetup show=$showSetup")

        val issuer = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val holder = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val (issuerX, issuerY) = coordinates(issuer.public as ECPublicKey)
        val (holderX, holderY) = coordinates(holder.public as ECPublicKey)

        val disclosure = b64url("[\"fixed-test-salt\",\"birthdate\",\"1990-01-01\"]".toByteArray())
        val digest = b64url(MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray()))

        val header = b64url(
            JSONObject().put("alg", "ES256").put("typ", "vc+sd-jwt").toString().toByteArray()
        )
        val payload = b64url(
            JSONObject()
                .put("iss", "did:key:openac-age-test-issuer")
                .put("nbf", 1)
                .put("exp", 4_102_444_800L)
                .put(
                    "cnf",
                    JSONObject().put(
                        "jwk",
                        JSONObject()
                            .put("kty", "EC")
                            .put("crv", "P-256")
                            .put("x", holderX)
                            .put("y", holderY)
                    )
                )
                .put(
                    "vc",
                    JSONObject().put(
                        "credentialSubject",
                        // Android's org.json.JSONObject.put(String, Collection) is
                        // unreliable across API levels - build the JSONArray explicitly.
                        JSONObject().put("_sd_alg", "sha-256").put("_sd", JSONArray().put(digest))
                    )
                )
                .toString()
                .toByteArray()
        )
        val signingInput = "$header.$payload"
        val issuerSig = b64url(signRaw(issuer.private, signingInput.toByteArray()))
        val sdJwt = "$signingInput.$issuerSig~$disclosure~"

        val prepared = createAgePrepareInput(documentsPath, sdJwt, issuerX, issuerY)
        val jwtTiming = proveJwt(documentsPath)
        Log.i(TAG, "prove_jwt: totalMs=${jwtTiming.totalMs}")

        val nonce = "fixed-openac-age-request-nonce-0123456789"
        val holderSig = b64url(signRaw(holder.private, nonce.toByteArray()))
        val cutoff = 2008_0901UL
        createAgeShowInput(
            documentsPath, nonce, holderSig, prepared.claimName, prepared.claimFormat, cutoff
        )
        val showTiming = proveShow(documentsPath)
        Log.i(TAG, "prove_show: totalMs=${showTiming.totalMs}")

        generateSharedBlinds(documentsPath)
        reblindJwt(documentsPath)
        reblindShow(documentsPath)

        val accepted = verifyAgePresentation(
            documentsPath, nonce, prepared.claimName, prepared.claimFormat, cutoff, issuerX, issuerY
        )
        check(accepted) { "linked age proof rejected its own fixed vector" }
        return "prepare=${jwtTiming.totalMs}ms show=${showTiming.totalMs}ms"
    }

    /** Base64url, no padding - matches Rust's URL_SAFE_NO_PAD. */
    private fun b64url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    /** Raw (x, y) P-256 point coordinates, base64url - matches p256's to_encoded_point(false). */
    private fun coordinates(key: ECPublicKey): Pair<String, String> {
        val x = key.w.affineX.toFixedBytes(32)
        val y = key.w.affineY.toFixedBytes(32)
        return b64url(x) to b64url(y)
    }

    private fun BigInteger.toFixedBytes(len: Int): ByteArray {
        val raw = toByteArray()
        val trimmed = if (raw.size > len) raw.copyOfRange(raw.size - len, raw.size) else raw
        val out = ByteArray(len)
        System.arraycopy(trimmed, 0, out, len - trimmed.size, trimmed.size)
        return out
    }

    /**
     * SHA256withECDSA via the default provider yields a DER-encoded
     * SEQUENCE{INTEGER r, INTEGER s}; p256::ecdsa::Signature::to_bytes()
     * (what the Rust side/circuit expects) is the raw 64-byte r||s (IEEE
     * P1363) form instead. Convert.
     */
    private fun signRaw(key: PrivateKey, message: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(key)
            update(message)
        }.sign()
        val (r, s) = parseDerEcdsaSignature(der)
        return r.toFixedBytes(32) + s.toFixedBytes(32)
    }

    private fun parseDerEcdsaSignature(der: ByteArray): Pair<BigInteger, BigInteger> {
        require(der[0] == 0x30.toByte()) { "not a DER SEQUENCE" }
        var offset = 2
        if ((der[1].toInt() and 0x80) != 0) offset += (der[1].toInt() and 0x7F)
        fun readInt(): BigInteger {
            require(der[offset] == 0x02.toByte()) { "not a DER INTEGER" }
            val len = der[offset + 1].toInt()
            val start = offset + 2
            val value = BigInteger(1, der.copyOfRange(start, start + len))
            offset = start + len
            return value
        }
        val r = readInt()
        val s = readInt()
        return r to s
    }
}
