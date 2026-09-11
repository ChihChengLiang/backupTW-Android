package tw.bonds.backuptw.wallet

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * One entry in a credential's own activity log - matches the official
 * TWDIW app's "Credential History" screen (an "added" entry per
 * received card, an "authorization" entry per presentation). Purely
 * presentational metadata: no claim *values* live here, only what was
 * disclosed and to whom - see [Authorized.disclosedFieldsLabel].
 */
sealed interface CredentialHistoryEvent {
    val timestampUnixMillis: Long

    data class Added(override val timestampUnixMillis: Long, val credentialDisplayName: String) : CredentialHistoryEvent

    data class Authorized(
        override val timestampUnixMillis: Long,
        val organisationName: String,
        val purpose: String,
        val vcNo: String?,
        val disclosedFieldsLabel: String,
    ) : CredentialHistoryEvent
}

/**
 * One encrypted file per credential id, holding a JSON array of that
 * credential's [CredentialHistoryEvent]s - same shape as
 * [TrustSnapshotStore] (`EncryptedFile`, delete-then-write for
 * "replace"), just keyed by the same id [CredentialStore] uses rather
 * than an issuer DID. Low write volume (one event per add/presentation),
 * so `append` is a plain read-modify-write rather than anything
 * incremental.
 */
class CredentialHistoryStore(context: Context) {
    private val appContext = context.applicationContext
    private val directory: File = File(appContext.filesDir, "credential_history").apply { mkdirs() }
    private val masterKey =
        MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

    fun append(credentialId: String, event: CredentialHistoryEvent) {
        val events = load(credentialId) + event
        val file = fileFor(credentialId)
        if (file.exists()) file.delete()
        val json = JSONArray().apply { events.forEach { put(toJson(it)) } }
        encryptedFile(file).openFileOutput().use { it.write(json.toString().toByteArray(Charsets.UTF_8)) }
    }

    fun load(credentialId: String): List<CredentialHistoryEvent> {
        val file = fileFor(credentialId)
        if (!file.exists()) return emptyList()
        val text = encryptedFile(file).openFileInput().use { it.readBytes().toString(Charsets.UTF_8) }
        val array = JSONArray(text)
        return (0 until array.length()).map { fromJson(array.getJSONObject(it)) }
    }

    private fun toJson(event: CredentialHistoryEvent): JSONObject =
        when (event) {
            is CredentialHistoryEvent.Added ->
                JSONObject()
                    .put("type", "added")
                    .put("timestampUnixMillis", event.timestampUnixMillis)
                    .put("credentialDisplayName", event.credentialDisplayName)
            is CredentialHistoryEvent.Authorized ->
                JSONObject()
                    .put("type", "authorized")
                    .put("timestampUnixMillis", event.timestampUnixMillis)
                    .put("organisationName", event.organisationName)
                    .put("purpose", event.purpose)
                    .put("vcNo", event.vcNo ?: JSONObject.NULL)
                    .put("disclosedFieldsLabel", event.disclosedFieldsLabel)
        }

    private fun fromJson(json: JSONObject): CredentialHistoryEvent =
        when (json.getString("type")) {
            "added" ->
                CredentialHistoryEvent.Added(
                    timestampUnixMillis = json.getLong("timestampUnixMillis"),
                    credentialDisplayName = json.getString("credentialDisplayName"),
                )
            else ->
                CredentialHistoryEvent.Authorized(
                    timestampUnixMillis = json.getLong("timestampUnixMillis"),
                    organisationName = json.getString("organisationName"),
                    purpose = json.getString("purpose"),
                    vcNo = if (json.isNull("vcNo")) null else json.getString("vcNo"),
                    disclosedFieldsLabel = json.getString("disclosedFieldsLabel"),
                )
        }

    private fun fileFor(credentialId: String): File {
        require(credentialId.isNotEmpty() && credentialId.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
            "unsafe credential id"
        }
        return File(directory, "$credentialId.json")
    }

    private fun encryptedFile(file: File) =
        EncryptedFile.Builder(appContext, file, masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
            .build()
}
