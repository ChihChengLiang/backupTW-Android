package tw.bonds.backuptw.wallet

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.io.File

/**
 * The minimum evidence an offline verifier needs to decide that a TWDIW
 * issuer was accepted previously by both independent trust channels (the
 * API trust list and the Arbitrum registry) - mirrors iOS's
 * `OfflineIssuerTrustSnapshot`. No credential identifier, holder DID,
 * disclosure or subject field lives here; this is issuer-wide public
 * registry material, kept so an offline pickup can re-confirm an
 * issuer's standing without a network round trip.
 */
data class TrustSnapshot(
    val issuerDid: String,
    val displayName: String,
    val taxId: String,
    val apiUpdatedAt: Long?,
    val verifiedAt: Long,
    val network: String,
    val contractAddress: String,
    val blockNumber: String,
    val transactionHash: String,
)

/** One encrypted file per issuer DID, base64url-named to stay filesystem-safe. */
class TrustSnapshotStore(context: Context) {
    private val appContext = context.applicationContext
    private val directory: File = File(appContext.filesDir, "trust_snapshots").apply { mkdirs() }
    private val masterKey =
        MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

    fun save(snapshot: TrustSnapshot) {
        val file = fileFor(snapshot.issuerDid)
        if (file.exists()) file.delete()
        val json = JSONObject().apply {
            put("issuerDid", snapshot.issuerDid)
            put("displayName", snapshot.displayName)
            put("taxId", snapshot.taxId)
            put("apiUpdatedAt", snapshot.apiUpdatedAt ?: JSONObject.NULL)
            put("verifiedAt", snapshot.verifiedAt)
            put("network", snapshot.network)
            put("contractAddress", snapshot.contractAddress)
            put("blockNumber", snapshot.blockNumber)
            put("transactionHash", snapshot.transactionHash)
        }
        encryptedFile(file).openFileOutput().use { it.write(json.toString().toByteArray(Charsets.UTF_8)) }
    }

    fun load(issuerDid: String): TrustSnapshot? {
        val file = fileFor(issuerDid)
        if (!file.exists()) return null
        val text = encryptedFile(file).openFileInput().use { it.readBytes().toString(Charsets.UTF_8) }
        val json = JSONObject(text)
        return TrustSnapshot(
            issuerDid = json.getString("issuerDid"),
            displayName = json.getString("displayName"),
            taxId = json.getString("taxId"),
            apiUpdatedAt = if (json.isNull("apiUpdatedAt")) null else json.getLong("apiUpdatedAt"),
            verifiedAt = json.getLong("verifiedAt"),
            network = json.getString("network"),
            contractAddress = json.getString("contractAddress"),
            blockNumber = json.getString("blockNumber"),
            transactionHash = json.getString("transactionHash"),
        )
    }

    private fun fileFor(issuerDid: String): File {
        val name = android.util.Base64.encodeToString(
            issuerDid.toByteArray(Charsets.UTF_8),
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING,
        )
        return File(directory, "$name.json")
    }

    private fun encryptedFile(file: File) =
        EncryptedFile.Builder(appContext, file, masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
            .build()
}
