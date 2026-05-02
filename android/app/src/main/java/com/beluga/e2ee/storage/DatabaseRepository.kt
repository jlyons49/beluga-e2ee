package com.beluga.e2ee.storage

import android.content.Context
import com.beluga.e2ee.crypto.Base85
import org.json.JSONObject

/**
 * Typed accessors over the encrypted JSON database.
 * Direct port of Python's jsonDatabase class.
 *
 * Database JSON schema:
 *   {
 *     "signingKey": "<base64 PKCS8 DER string | null>",
 *     "sessionKeys": { "<userId>": "<base85 32-byte session key>" },
 *     "publicKeys":  { "<userId>": "<base85 compressed-point bytes>" }
 *   }
 */
class DatabaseRepository(context: Context) {

    private val encryptedDb = EncryptedDatabase(context)
    private var passwordKey: ByteArray? = null
    private var db: JSONObject? = null

    val isUnlocked: Boolean get() = db != null

    /**
     * Derives the key from the password and attempts to load the database.
     * Returns false if the password is wrong (AEADBadTagException).
     */
    fun unlock(password: String): Boolean {
        return try {
            val key = encryptedDb.deriveKey(password)
            val loaded = encryptedDb.load(key)
            passwordKey = key
            db = loaded
            true
        } catch (e: Exception) {
            // AEADBadTagException means wrong password or corrupted file
            false
        }
    }

    fun lock() {
        passwordKey?.fill(0)
        passwordKey = null
        db = null
    }

    // --- Session keys ---

    fun saveSessionKey(userId: String, key: ByteArray) {
        sessionKeys().put(userId, Base85.encode(key))
        flush()
    }

    fun getSessionKey(userId: String): ByteArray {
        val encoded = sessionKeys().optString(userId, null)
            ?: throw NoSuchElementException("No session key for user '$userId'")
        return Base85.decode(encoded)
    }

    fun removeSession(userId: String) {
        sessionKeys().remove(userId)
        flush()
    }

    fun hasSession(userId: String): Boolean = sessionKeys().has(userId)

    // --- Signing key ---

    fun setSigningKey(base64Pkcs8: String) {
        database().put("signingKey", base64Pkcs8)
        flush()
    }

    fun getSigningKey(): String =
        database().optString("signingKey", null)
            ?: throw NoSuchElementException("No signing key in database")

    fun hasSigningKey(): Boolean = !database().isNull("signingKey")

    // --- Peer public keys ---

    fun storePublicKey(userId: String, publicKeyBytes: ByteArray) {
        publicKeys().put(userId, Base85.encode(publicKeyBytes))
        flush()
    }

    fun getPublicKey(userId: String): ByteArray {
        val encoded = publicKeys().optString(userId, "")
            .takeIf { it.isNotEmpty() }
            ?: throw NoSuchElementException("No public key for user '$userId'")
        return Base85.decode(encoded)
    }

    fun removePublicKey(userId: String) {
        publicKeys().remove(userId)
        // Also remove the session if one exists
        if (hasSession(userId)) removeSession(userId)
        flush()
    }

    fun getAllContactIds(): List<String> {
        val keys = publicKeys()
        return (0 until keys.length()).map { keys.names()?.getString(it) ?: "" }.filter { it.isNotEmpty() }
    }

    // --- Helpers ---

    private fun database(): JSONObject = db ?: error("Database not unlocked")

    private fun sessionKeys(): JSONObject {
        val d = database()
        if (!d.has("sessionKeys")) d.put("sessionKeys", JSONObject())
        return d.getJSONObject("sessionKeys")
    }

    private fun publicKeys(): JSONObject {
        val d = database()
        if (!d.has("publicKeys")) d.put("publicKeys", JSONObject())
        return d.getJSONObject("publicKeys")
    }

    private fun flush() {
        val key = passwordKey ?: error("Database not unlocked")
        encryptedDb.save(key, database())
    }
}
