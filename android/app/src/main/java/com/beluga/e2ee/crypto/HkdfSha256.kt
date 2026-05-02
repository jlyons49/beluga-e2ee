package com.beluga.e2ee.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Manual RFC 5869 HKDF-SHA-256.
 *
 * Android JCA's KDF API requires API 31+; this implementation works from API 26.
 * Matches Python: HKDF(SHA256, length, salt, info).derive(ikm)
 *   - salt=None  → 32 zero bytes per RFC 5869 §2.2
 *   - info=None  → empty byte array
 */
object HkdfSha256 {

    private const val ALGORITHM = "HmacSHA256"
    private const val HASH_LEN = 32

    fun derive(
        ikm: ByteArray,
        salt: ByteArray? = null,
        info: ByteArray = ByteArray(0),
        length: Int = 32
    ): ByteArray {
        val prk = extract(salt, ikm)
        return expand(prk, info, length)
    }

    private fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return hmac(effectiveSalt, ikm)
    }

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length > 0 && length <= 255 * HASH_LEN) { "HKDF length out of range" }
        val result = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte()))
            val copyLen = minOf(HASH_LEN, length - offset)
            t.copyInto(result, offset, 0, copyLen)
            offset += copyLen
            counter++
        }
        return result
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(key, ALGORITHM))
        return mac.doFinal(data)
    }
}
