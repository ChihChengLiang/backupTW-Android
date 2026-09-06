package tw.bonds.backuptw.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.backuptw_core.TwdiwIssuer
import uniffi.backuptw_core.parseIssuerTrustListPage

private const val TRUST_LIST_BASE = "https://frontend.wallet.gov.tw/api/did?size=20&orgType=1&status=1"

/**
 * Fetches the live TWDIW trust list in full. Pages until a page comes
 * back empty rather than computing offsets from `size` - the production
 * API clamps the page size and derives the offset from it, so requesting
 * beyond the clamp returns nothing at all (see the endpoint notes in the
 * session plan).
 */
object IssuerTrustList {
    /** A defensive upper bound: production sits around 43 entries across ~3 pages of 20. */
    private const val MAX_PAGES = 25

    suspend fun fetchAll(): List<TwdiwIssuer> =
        withContext(Dispatchers.IO) {
            val all = mutableListOf<TwdiwIssuer>()
            var page = 0
            while (page < MAX_PAGES) {
                val body = TwdiwClient.get("$TRUST_LIST_BASE&page=$page")
                val issuers = parseIssuerTrustListPage(body)
                if (issuers.isEmpty()) break
                all.addAll(issuers)
                page += 1
            }
            all
        }
}
