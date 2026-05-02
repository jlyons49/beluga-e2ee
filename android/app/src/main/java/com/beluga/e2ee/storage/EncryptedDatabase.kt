package com.beluga.e2ee.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.beluga.e2ee.crypto.Base85
import com.beluga.e2ee.crypto.HkdfSha256
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory

/**
 * Encrypted on-disk JSON database, replacing Python's fileencrypter.py.
 *
 * Security improvements over Python:
 *   1. Random per-installation salt (fixes hardcoded 'girefub3' salt).
 *      Salt is stored in EncryptedSharedPreferences (Android Keystore-backed).
 *   2. PBKDF2WithHmacSHA256 (300k iterations) + HKDF-SHA256 key derivation
 *      replaces Python's single fast HKDF, making brute-force attacks slower.
 *
 * File format: JSON {"iv": "<b85>", "tag": "<b85>", "ct": "<b85>"}
 *   — identical structure to Python for potential future migration.
 */
class EncryptedDatabase(private val context: Context) {

    companion object {
        private const val DB_FILE = "database.bin"
        private const val PREFS_NAME = "beluga_secure_prefs"
        private const val KEY_SALT = "db_salt"
        private const val PBKDF2_ITERATIONS = 300_000
        private const val KEY_LENGTH_BITS = 256
    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val securePrefs = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /** Returns the per-installation random salt, generating it on first run. */
    private fun getOrCreateSalt(): ByteArray {
        val existing = securePrefs.getString(KEY_SALT, null)
        if (existing != null) return Base85.decode(existing)
        val newSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        securePrefs.edit().putString(KEY_SALT, Base85.encode(newSalt)).apply()
        return newSalt
    }

    /**
     * Derives a 32-byte AES key from the password.
     * PBKDF2 (300k iterations, random salt) → HKDF-SHA256 → 32-byte key.
     */
    fun deriveKey(password: String): ByteArray {
        val salt = getOrCreateSalt()
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val pbkdf2Out = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return HkdfSha256.derive(pbkdf2Out, salt = null, info = ByteArray(0), length = 32)
    }

    fun exists(): Boolean = File(context.filesDir, DB_FILE).exists()

    /** Decrypts and parses the database JSON. Throws AEADBadTagException on wrong password. */
    fun load(key: ByteArray): JSONObject {
        val file = File(context.filesDir, DB_FILE)
        if (!file.exists()) {
            return JSONObject("""{"signingKey":null,"sessionKeys":{},"publicKeys":{}}""")
        }
        val fileJson = JSONObject(file.readText(Charsets.UTF_8))
        val iv = Base85.decode(fileJson.getString("iv"))
        val tag = Base85.decode(fileJson.getString("tag"))
        val ct = Base85.decode(fileJson.getString("ct"))

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val plaintext = cipher.doFinal(ct + tag)
        return JSONObject(plaintext.toString(Charsets.UTF_8))
    }

    /** Serializes and encrypts the database JSON to disk. */
    fun save(key: ByteArray, db: JSONObject) {
        val plaintext = db.toString().toByteArray(Charsets.UTF_8)
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val output = cipher.doFinal(plaintext)
        val ct = output.copyOf(output.size - 16)
        val tag = output.copyOfRange(output.size - 16, output.size)

        val fileJson = JSONObject().apply {
            put("iv", Base85.encode(iv))
            put("tag", Base85.encode(tag))
            put("ct", Base85.encode(ct))
        }
        File(context.filesDir, DB_FILE).writeText(fileJson.toString(), Charsets.UTF_8)
    }
}
