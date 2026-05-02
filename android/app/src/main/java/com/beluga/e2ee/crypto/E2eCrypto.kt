package com.beluga.e2ee.crypto

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

/**
 * Core cryptographic primitives — direct Kotlin port of e2ecrypto.py.
 *
 * All operations are wire-compatible with the Python beluga client:
 *   - SECP384R1 / P-384 curve
 *   - AES-256-GCM with 16-byte IV and 128-bit tag
 *   - ECDSA-SHA256 signatures
 *   - HKDF-SHA256 (no salt, no info) for ECDH key derivation
 *   - zlib (RFC 1950) compression before encryption
 *   - X9.62 compressed-point public key encoding (49 bytes for P-384)
 *
 * GCM IV note: Python uses os.urandom(16) — 16-byte IV is non-standard
 * (spec recommends 12) but functionally valid. Kept for wire compatibility.
 *
 * Null-byte padding: Python prepends \0 bytes to align compressed data to
 * a 16-byte boundary before encryption. Kept on both encrypt and decrypt
 * paths for cross-platform compatibility.
 */
object E2eCrypto {

    private const val CURVE = "secp384r1"
    private const val EC_PROVIDER = "BC"

    // --- Key generation ---

    fun generateKeyPair(): KeyPair {
        val kg = KeyPairGenerator.getInstance("EC", EC_PROVIDER)
        kg.initialize(ECNamedCurveTable.getParameterSpec(CURVE), SecureRandom())
        return kg.generateKeyPair()
    }

    // --- Public key serialization (X9.62 compressed point — wire format) ---

    /** Returns X9.62 compressed point bytes (49 bytes for P-384). */
    fun publicKeyToBytes(publicKey: PublicKey): ByteArray {
        val bcKey = publicKey as org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
        return bcKey.q.getEncoded(true)
    }

    /** Reconstructs a PublicKey from X9.62 compressed point bytes. */
    fun bytesToPublicKey(bytes: ByteArray): PublicKey {
        val params = ECNamedCurveTable.getParameterSpec(CURVE)
        val point = params.curve.decodePoint(bytes)
        val spec = ECPublicKeySpec(point, params)
        return KeyFactory.getInstance("EC", EC_PROVIDER).generatePublic(spec)
    }

    // --- Private key serialization (PKCS8 base64 — stored inside encrypted DB) ---

    /** Serializes private key to base64-encoded PKCS8 DER. Stored in encrypted DB. */
    fun privateKeyToBase64(privateKey: PrivateKey): String =
        Base64.getEncoder().encodeToString(privateKey.encoded)

    /** Loads private key from base64-encoded PKCS8 DER. */
    fun base64ToPrivateKey(b64: String): PrivateKey {
        val bytes = Base64.getDecoder().decode(b64)
        return KeyFactory.getInstance("EC", EC_PROVIDER).generatePrivate(PKCS8EncodedKeySpec(bytes))
    }

    // --- ECDH + HKDF key derivation ---

    /**
     * Performs ECDH exchange and derives a 32-byte session key.
     * Matches Python: HKDF(SHA256, 32, salt=None, info=None).derive(shared_secret)
     */
    fun performEcdh(localPrivate: PrivateKey, remotePublic: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH", EC_PROVIDER)
        ka.init(localPrivate)
        ka.doPhase(remotePublic, true)
        val sharedSecret = ka.generateSecret()
        return HkdfSha256.derive(sharedSecret, salt = null, info = ByteArray(0), length = 32)
    }

    // --- AES-256-GCM ---

    data class EncryptResult(val ciphertext: ByteArray, val iv: ByteArray, val tag: ByteArray)

    /**
     * Compresses, null-pads, then AES-256-GCM encrypts.
     * Returns ciphertext, iv, and tag separately (matching Python wire format).
     */
    fun encrypt(plaintext: ByteArray, key: ByteArray): EncryptResult {
        val compressed = zlibCompress(plaintext)
        val padded = nullPadTo16(compressed)
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        // Java GCM appends 16-byte tag at the end of doFinal output
        val output = cipher.doFinal(padded)
        val ciphertext = output.copyOf(output.size - 16)
        val tag = output.copyOfRange(output.size - 16, output.size)
        return EncryptResult(ciphertext, iv, tag)
    }

    /**
     * AES-256-GCM decrypts, strips null padding, then decompresses.
     * Throws AEADBadTagException if tag/key is wrong (matches Python RuntimeError).
     */
    fun decrypt(ciphertext: ByteArray, iv: ByteArray, tag: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        // Java GCM expects ciphertext + tag concatenated
        val padded = cipher.doFinal(ciphertext + tag)
        // Strip null bytes from both ends, matching Python's .strip(b'\0')
        val compressed = padded
            .dropWhile { it == 0.toByte() }
            .dropLastWhile { it == 0.toByte() }
            .toByteArray()
        return zlibDecompress(compressed)
    }

    // --- ECDSA-SHA256 ---

    fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA", EC_PROVIDER)
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    fun verify(data: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA", EC_PROVIDER)
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: SignatureException) {
            false
        }
    }

    // --- zlib (RFC 1950 format — compatible with Python zlib.compress/decompress) ---

    private fun zlibCompress(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, false) // nowrap=false → zlib header
        deflater.setInput(data)
        deflater.finish()
        val bos = ByteArrayOutputStream(data.size + 64)
        val buf = ByteArray(4096)
        while (!deflater.finished()) {
            val count = deflater.deflate(buf)
            bos.write(buf, 0, count)
        }
        deflater.end()
        return bos.toByteArray()
    }

    private fun zlibDecompress(data: ByteArray): ByteArray {
        val inflater = Inflater(false) // nowrap=false → zlib header
        inflater.setInput(data)
        val bos = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (!inflater.finished()) {
            val count = inflater.inflate(buf)
            if (count > 0) bos.write(buf, 0, count)
        }
        inflater.end()
        return bos.toByteArray()
    }

    private fun nullPadTo16(data: ByteArray): ByteArray {
        val remainder = data.size % 16
        if (remainder == 0) return data
        return ByteArray(16 - remainder) + data
    }
}
