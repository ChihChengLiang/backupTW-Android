package tw.bonds.backuptw.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.backuptw_core.TwdiwIssuer
import uniffi.backuptw_core.parseIssuerTrustListPage

private const val TRUST_LIST_BASE = "https://frontend.wallet.gov.tw/api/did"

/**
 * Fetches the live TWDIW trust list in full, both organisation types.
 * `orgType=1` covers issuers (the telecom carriers M3 needs); `orgType=2`
 * covers services/verifiers (7-Eleven's own registration, which M4 needs) -
 * measured off `TrustListFetcher.swift`'s `fetchAll`, which fetches both
 * for exactly this reason and dedupes by DID afterward (an organisation
 * registered as both, e.g. 行政院-數位發展部, would otherwise appear twice
 * and make the issuer gate see an ambiguity that is not one).
 *
 * Pages until a page comes back empty rather than computing offsets from
 * `size` - the production API clamps the page size and derives the offset
 * from it, so requesting beyond the clamp returns nothing at all.
 */
object IssuerTrustList {
    /** A defensive upper bound per org type: production sits around 43 entries total. */
    private const val MAX_PAGES_PER_TYPE = 25

    suspend fun fetchAll(): List<TwdiwIssuer> =
        withContext(Dispatchers.IO) {
            val all = mutableListOf<TwdiwIssuer>()
            for (orgType in listOf(1, 2)) {
                var page = 0
                while (page < MAX_PAGES_PER_TYPE) {
                    val body = TwdiwClient.get("$TRUST_LIST_BASE?size=20&page=$page&orgType=$orgType&status=1")
                    val issuers = parseIssuerTrustListPage(body)
                    if (issuers.isEmpty()) break
                    all.addAll(issuers)
                    page += 1
                }
            }
            val seen = mutableSetOf<String>()
            all.filter { seen.add(it.did) }
        }
}
