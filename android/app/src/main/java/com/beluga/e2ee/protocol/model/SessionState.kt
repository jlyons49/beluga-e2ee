package com.beluga.e2ee.protocol.model

import java.security.PrivateKey

/** In-memory state during a session establishment handshake. Discarded after completion. */
data class SessionState(
    val activePrivateSecret: PrivateKey? = null,
    val pendingChunks: MutableMap<String, PendingMultiChunk> = mutableMapOf()
)

/** Accumulates multi-part ciphertext chunks until all arrive. Keyed by base85 tag. */
data class PendingMultiChunk(
    val total: Int,
    val iv: String,
    val tag: String,
    val chunks: MutableMap<Int, String> = mutableMapOf()
)
