package tw.bonds.backuptw.wallet

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * A non-2xx reply, carrying the server's own body so a refusal can be
 * read rather than guessed - the same lever every `*Error.badStatus`
 * case in the Swift source keeps.
 */
class TwdiwHttpException(val statusCode: Int, val bodyText: String?) : IOException("HTTP $statusCode")

/**
 * The one HTTP client this app makes real network calls through - see
 * `docs/2026-09-05-twdiw-protocol-notes.md` and
 * `docs/2026-09-05-telecom-pickup-notes.md` for the endpoints this talks
 * to. Every response is untrusted input: nothing here parses JSON or
 * makes a trust decision - it hands raw bytes to `core/`'s already-tested
 * parsers, exactly as the architecture boundary
 * (`docs/2026-09-05-decisions-and-roadmap.md`) requires. Blocking calls;
 * callers dispatch to `Dispatchers.IO`.
 */
object TwdiwClient {
    private val client =
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()

    fun get(url: String): ByteArray {
        val request = Request.Builder().url(url).get().build()
        return execute(request)
    }

    fun getText(url: String): String = get(url).toString(Charsets.UTF_8)

    fun postJson(url: String, jsonBody: String, bearerToken: String? = null): ByteArray {
        val builder =
            Request.Builder()
                .url(url)
                .post(jsonBody.toRequestBody("application/json".toMediaType()))
        if (bearerToken != null) builder.addHeader("Authorization", "Bearer $bearerToken")
        return execute(builder.build())
    }

    /** `encodedBody` is already `application/x-www-form-urlencoded` text - see `core`'s `formEncode`. */
    fun postFormEncoded(url: String, encodedBody: String): ByteArray {
        val request =
            Request.Builder()
                .url(url)
                .post(encodedBody.toRequestBody("application/x-www-form-urlencoded".toMediaType()))
                .build()
        return execute(request)
    }

    private fun execute(request: Request): ByteArray {
        client.newCall(request).execute().use { response ->
            val bytes = response.body?.bytes() ?: ByteArray(0)
            if (!response.isSuccessful) {
                throw TwdiwHttpException(response.code, bytes.toString(Charsets.UTF_8))
            }
            return bytes
        }
    }
}
