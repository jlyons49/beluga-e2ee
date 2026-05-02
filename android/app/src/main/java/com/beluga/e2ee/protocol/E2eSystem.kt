package com.beluga.e2ee.protocol

import com.beluga.e2ee.crypto.Base85
import com.beluga.e2ee.crypto.E2eCrypto
import com.beluga.e2ee.protocol.model.PendingMultiChunk
import com.beluga.e2ee.protocol.model.QrMessage
import com.beluga.e2ee.protocol.model.SessionState
import com.beluga.e2ee.storage.DatabaseRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import java.security.PublicKey

/**
 * Central orchestrator — direct port of Python's e2eSystem class.
 *
 * All methods are suspend functions; call from a coroutine on Dispatchers.IO
 * (key generation and crypto operations can block).
 *
 * Chunk size is 400 bytes of ciphertext (up from Python's 140 bytes).
 * At ERROR_CORRECT_M, this fits in a version-10 QR code and scans reliably.
 */
class E2eSystem(private val repo: DatabaseRepository) {

    companion object {
        private const val CHUNK_SIZE_BYTES = 400
    }

    private var sessionState = SessionState()

    /** Call once after unlock. Auto-generates a signing key pair if none exists. */
    suspend fun initialize() = withContext(Dispatchers.IO) {
        if (!repo.hasSigningKey()) {
            val pair = E2eCrypto.generateKeyPair()
            repo.setSigningKey(E2eCrypto.privateKeyToBase64(pair.private))
        }
    }

    // --- Send ---

    /**
     * Encrypts message for userId and returns a list of QR JSON strings.
     * Returns a single-element list for short messages; multi-element for large ones.
     * Mirrors Python's sendEncryptedMessage.
     */
    suspend fun sendEncryptedMessage(userId: String, message: String): List<String> =
        withContext(Dispatchers.IO) {
            val key = repo.getSessionKey(userId)
            val result = E2eCrypto.encrypt(message.toByteArray(Charsets.UTF_8), key)
            val ivB85  = Base85.encode(result.iv)
            val tagB85 = Base85.encode(result.tag)
            val ct = result.ciphertext

            if (ct.size <= CHUNK_SIZE_BYTES) {
                listOf(QrMessageParser.serialize(
                    QrMessage.SingleChunk(iv = ivB85, ct = Base85.encode(ct), tag = tagB85)
                ))
            } else {
                val chunkCount = (ct.size + CHUNK_SIZE_BYTES - 1) / CHUNK_SIZE_BYTES
                (0 until chunkCount).map { i ->
                    val chunk = ct.copyOfRange(
                        i * CHUNK_SIZE_BYTES,
                        minOf((i + 1) * CHUNK_SIZE_BYTES, ct.size)
                    )
                    QrMessageParser.serialize(
                        QrMessage.MultiChunk(
                            index = i,
                            total = chunkCount,
                            iv    = ivB85,
                            ct    = Base85.encode(chunk),
                            tag   = tagB85
                        )
                    )
                }
            }
        }

    // --- Receive ---

    /**
     * Handles an incoming encrypted QR message (modes 1 and 2).
     * Returns decrypted plaintext when the message is complete,
     * or null if more chunks are still needed (mode 2 partial).
     */
    suspend fun receiveMessage(userId: String, msg: QrMessage): String? =
        withContext(Dispatchers.IO) {
            when (msg) {
                is QrMessage.SingleChunk -> {
                    val key = repo.getSessionKey(userId)
                    E2eCrypto.decrypt(
                        Base85.decode(msg.ct),
                        Base85.decode(msg.iv),
                        Base85.decode(msg.tag),
                        key
                    ).toString(Charsets.UTF_8)
                }
                is QrMessage.MultiChunk -> {
                    val pending = sessionState.pendingChunks.getOrPut(msg.tag) {
                        PendingMultiChunk(total = msg.total, iv = msg.iv, tag = msg.tag)
                    }
                    pending.chunks[msg.index] = msg.ct
                    if (pending.chunks.size < pending.total) return@withContext null

                    // All chunks received — reassemble and decrypt
                    val combined = (0 until pending.total)
                        .map { Base85.decode(pending.chunks[it]!!) }
                        .reduce { acc, bytes -> acc + bytes }
                    sessionState.pendingChunks.remove(msg.tag)

                    val key = repo.getSessionKey(userId)
                    E2eCrypto.decrypt(
                        combined,
                        Base85.decode(pending.iv),
                        Base85.decode(pending.tag),
                        key
                    ).toString(Charsets.UTF_8)
                }
                else -> null
            }
        }

    // --- Session establishment ---

    /**
     * Initiates a session with userId (we send the first QR).
     * Requires that userId's public key is already stored.
     * Returns a mode-3 QR JSON string, or null if no public key exists.
     * Mirrors Python's initializeSession.
     */
    suspend fun initializeSession(userId: String): String? = withContext(Dispatchers.IO) {
        if (!repo.getAllContactIds().contains(userId)) return@withContext null

        val ephemeral = E2eCrypto.generateKeyPair()
        val pubBytes = E2eCrypto.publicKeyToBytes(ephemeral.public)
        val signingKey = E2eCrypto.base64ToPrivateKey(repo.getSigningKey())
        val signature = E2eCrypto.sign(pubBytes, signingKey)

        sessionState = sessionState.copy(activePrivateSecret = ephemeral.private)

        QrMessageParser.serialize(
            QrMessage.SessionInit(sec = Base85.encode(pubBytes), sig = Base85.encode(signature))
        )
    }

    /**
     * Accepts a session-init QR from userId (mode 3 input).
     *
     * - Verifies the ECDSA signature on the received ephemeral public key.
     * - Completes ECDH and stores the shared session key.
     * - If we didn't initiate (responder path): generates our own ephemeral key,
     *   signs it, and returns a mode-3 reply QR for the peer to scan.
     * - If we initiated (initiator path): returns null (session is now complete).
     * - Returns null and does NOT save if signature verification fails.
     *
     * Mirrors Python's acceptSessionInit.
     */
    suspend fun acceptSessionInit(userId: String, msg: QrMessage.SessionInit): String? =
        withContext(Dispatchers.IO) {
            val peerPublicKey: PublicKey = try {
                E2eCrypto.bytesToPublicKey(repo.getPublicKey(userId))
            } catch (e: NoSuchElementException) {
                return@withContext null
            }

            val receivedSecretBytes = Base85.decode(msg.sec)
            val receivedSigBytes    = Base85.decode(msg.sig)

            if (!E2eCrypto.verify(receivedSecretBytes, receivedSigBytes, peerPublicKey)) {
                return@withContext null
            }

            val receivedPublic = E2eCrypto.bytesToPublicKey(receivedSecretBytes)
            val weInitiated = sessionState.activePrivateSecret != null

            val ourEphemeralPrivate = if (weInitiated) {
                sessionState.activePrivateSecret!!
            } else {
                E2eCrypto.generateKeyPair().private  // responder generates a fresh pair
            }

            val sharedSecret = E2eCrypto.performEcdh(ourEphemeralPrivate, receivedPublic)
            repo.saveSessionKey(userId, sharedSecret)
            sessionState = sessionState.copy(activePrivateSecret = null)

            if (weInitiated) {
                null // Initiator: session is complete; no reply needed
            } else {
                // Responder: derive our public key from the fresh private key and return it
                val ourPubBytes = derivePublicBytes(ourEphemeralPrivate as BCECPrivateKey)
                val signingKey = E2eCrypto.base64ToPrivateKey(repo.getSigningKey())
                val sig = E2eCrypto.sign(ourPubBytes, signingKey)
                QrMessageParser.serialize(
                    QrMessage.SessionInit(sec = Base85.encode(ourPubBytes), sig = Base85.encode(sig))
                )
            }
        }

    // --- Public key sharing ---

    /**
     * Returns a mode-6 QR JSON containing our long-term signing public key.
     * Mirrors Python's sharePublicKeys.
     */
    suspend fun sharePublicKey(): String = withContext(Dispatchers.IO) {
        val signingPrivate = E2eCrypto.base64ToPrivateKey(repo.getSigningKey())
        val pubBytes = derivePublicBytes(signingPrivate as BCECPrivateKey)
        QrMessageParser.serialize(QrMessage.SharePublicKey(publickey = Base85.encode(pubBytes)))
    }

    /**
     * Stores the peer's long-term signing public key under userId.
     * Mirrors Python's receivePublicKey.
     */
    suspend fun receivePublicKey(userId: String, msg: QrMessage.SharePublicKey) =
        withContext(Dispatchers.IO) {
            repo.storePublicKey(userId, Base85.decode(msg.publickey))
        }

    /** Derives the X9.62 compressed-point public key bytes from a BCECPrivateKey. */
    private fun derivePublicBytes(privateKey: BCECPrivateKey): ByteArray {
        val params = ECNamedCurveTable.getParameterSpec("secp384r1")
        val q = params.g.multiply(privateKey.d).normalize()
        return q.getEncoded(true)
    }
}
