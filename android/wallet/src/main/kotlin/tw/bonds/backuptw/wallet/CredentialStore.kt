package tw.bonds.backuptw.wallet

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File

/**
 * One encrypted file per received credential, named by its
 * `credential_configuration_id` - mirrors iOS's `CredentialStore` (one
 * file per card; re-collecting the same configuration id replaces it,
 * which is what re-collection means). A credential is sensitive the
 * moment its selectively-disclosed fields could be read back out of
 * storage rather than only ever appearing signed in a presentation, so
 * this is `EncryptedFile` rather than a plain file - the Android
 * equivalent of iOS storing credentials under
 * `.completeUnlessOpen`/excluded from backup.
 */
class CredentialStore(context: Context) {
    private val appContext = context.applicationContext
    private val directory: File = File(appContext.filesDir, "credentials").apply { mkdirs() }
    private val masterKey =
        MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

    fun save(configurationId: String, serializedCredential: String) {
        val file = fileFor(configurationId)
        // EncryptedFile refuses to write over an existing file - deleting
        // first is how "replace" is expressed here, matching the atomic
        // overwrite iOS's `.write(to:options:.atomic)` performs.
        if (file.exists()) file.delete()
        encryptedFile(file).openFileOutput().use { it.write(serializedCredential.toByteArray(Charsets.UTF_8)) }
    }

    fun load(configurationId: String): String? {
        val file = fileFor(configurationId)
        if (!file.exists()) return null
        return encryptedFile(file).openFileInput().use { it.readBytes().toString(Charsets.UTF_8) }
    }

    fun delete(configurationId: String) {
        fileFor(configurationId).delete()
    }

    /** Every stored configuration id, for a card-selection screen. */
    fun allIds(): List<String> = directory.listFiles()?.mapNotNull { file ->
        file.name.takeIf { it.endsWith(".jws") }?.removeSuffix(".jws")
    } ?: emptyList()

    /**
     * `configurationId` is server-supplied (an offer's own
     * `credential_configuration_ids` entry) - trusted enough to collect
     * from once the issuer gates pass, but not enough to build a
     * filesystem path from unchecked. Fail closed on anything outside a
     * plain identifier's charset rather than trying to escape it, the
     * same discipline `core`'s own host/path normalisation uses.
     */
    private fun fileFor(configurationId: String): File {
        require(configurationId.isNotEmpty() && configurationId.all { it.isLetterOrDigit() || it == '_' || it == '-' }) {
            "unsafe credential configuration id"
        }
        return File(directory, "$configurationId.jws")
    }

    private fun encryptedFile(file: File) =
        EncryptedFile.Builder(appContext, file, masterKey, EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
            .build()
}
