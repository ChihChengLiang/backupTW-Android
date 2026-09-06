package tw.bonds.backuptw.wallet

import android.content.Context

private const val PREFS_NAME = "pending_card_application"
private const val KEY_VC_UID = "vc_uid"
private const val KEY_ALIAS = "alias"

/**
 * Which telecom card application is waiting on the carrier's own
 * phone-verification page, and the Keystore alias its proof must sign
 * with. Persisted to plain (unencrypted) `SharedPreferences` - neither
 * field is sensitive - since the carrier's page runs in an external
 * browser/app and Android may kill this process while the user is over
 * there; in-memory state alone would not survive that.
 */
data class PendingCardApplication(val vcUid: String, val alias: String)

object PendingCardApplicationStore {
    fun save(context: Context, application: PendingCardApplication) {
        prefs(context)
            .edit()
            .putString(KEY_VC_UID, application.vcUid)
            .putString(KEY_ALIAS, application.alias)
            .apply()
    }

    fun load(context: Context): PendingCardApplication? {
        val stored = prefs(context)
        val vcUid = stored.getString(KEY_VC_UID, null) ?: return null
        val alias = stored.getString(KEY_ALIAS, null) ?: return null
        return PendingCardApplication(vcUid, alias)
    }

    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
