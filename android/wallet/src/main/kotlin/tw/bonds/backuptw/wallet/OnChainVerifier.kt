package tw.bonds.backuptw.wallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.backuptw_core.TwdiwIssuer
import uniffi.backuptw_core.TwdiwOnChainVerification
import uniffi.backuptw_core.checkOnChainRecord
import uniffi.backuptw_core.currentRecordCallData
import uniffi.backuptw_core.decodeCurrentRecord
import uniffi.backuptw_core.isInfrastructureError

/**
 * Gate 1b's independent source: does the current Arbitrum registry state
 * agree with a trust-list issuer's own claim? Network shape (constants,
 * JSON-RPC batch) matches `core::twdiw::onchain`'s doc comments exactly -
 * that module owns the ABI encode/decode and the check itself; this is
 * only the HTTP leg, which stays native by design.
 */
object OnChainVerifier {
    private const val RPC_URL = "https://arb1.arbitrum.io/rpc"
    private const val NETWORK = "arbitrum"
    private const val REGISTRY_CONTRACT = "0x84172caf8dd126c76f1fa8a2733ca3233264d31f"

    suspend fun verify(issuer: TwdiwIssuer): TwdiwOnChainVerification =
        withContext(Dispatchers.IO) {
            val record =
                issuer.onChainRecords.firstOrNull {
                    it.network.lowercase() == NETWORK &&
                        it.contractAddress.lowercase() == REGISTRY_CONTRACT &&
                        it.status == 1L
                } ?: return@withContext TwdiwOnChainVerification.NotAnchored

            val callData = currentRecordCallData(issuer.did) ?: return@withContext TwdiwOnChainVerification.Unavailable

            val batch =
                JSONArray()
                    .put(rpcRequest(1, "eth_getTransactionByHash", JSONArray().put(record.transactionHash)))
                    .put(rpcRequest(2, "eth_getTransactionReceipt", JSONArray().put(record.transactionHash)))
                    .put(
                        rpcRequest(
                            3,
                            "eth_call",
                            JSONArray()
                                .put(JSONObject().put("to", REGISTRY_CONTRACT).put("data", callData))
                                .put("latest"),
                        ),
                    )

            val responseBytes =
                runCatching { TwdiwClient.postJson(RPC_URL, batch.toString()) }
                    .getOrElse { return@withContext TwdiwOnChainVerification.Unavailable }
            val responses = JSONArray(String(responseBytes, Charsets.UTF_8))
            val byId = mutableMapOf<Int, JSONObject>()
            for (i in 0 until responses.length()) {
                val reply = responses.getJSONObject(i)
                byId[reply.optInt("id")] = reply
            }

            if (byId.values.any { isInfrastructureError(it.toString()) }) {
                return@withContext TwdiwOnChainVerification.Unavailable
            }

            val transactionJson = byId[1]?.optJSONObject("result")?.toString()
            val receiptJson = byId[2]?.optJSONObject("result")?.toString()
            val currentRecordValue = byId[3]?.optString("result")
            val current = currentRecordValue?.let { decodeCurrentRecord(it) }

            checkOnChainRecord(issuer, record, transactionJson, receiptJson, current)
        }

    private fun rpcRequest(id: Int, method: String, params: JSONArray): JSONObject =
        JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", method)
            .put("params", params)
}
