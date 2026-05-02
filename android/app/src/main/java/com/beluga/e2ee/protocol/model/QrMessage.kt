package com.beluga.e2ee.protocol.model

/**
 * Sealed hierarchy for all QR message types.
 * Maps to Python's integer mode field:
 *   mode 1 → SingleChunk
 *   mode 2 → MultiChunk
 *   mode 3 → SessionInit
 *   mode 6 → SharePublicKey
 *
 * All string fields hold base85-encoded binary data, matching the Python wire format.
 */
sealed class QrMessage {

    data class SingleChunk(
        val iv: String,
        val ct: String,
        val tag: String
    ) : QrMessage()

    data class MultiChunk(
        val index: Int,
        val total: Int,
        val iv: String,
        val ct: String,
        val tag: String
    ) : QrMessage()

    data class SessionInit(
        val sec: String,
        val sig: String
    ) : QrMessage()

    data class SharePublicKey(
        val publickey: String
    ) : QrMessage()
}
