package com.beluga.e2ee

import com.beluga.e2ee.crypto.HkdfSha256
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.util.Base64

class HkdfSha256Test {

    // Vectors computed with Python stdlib hmac + hashlib (RFC 5869, SHA-256, salt=None→32 zeros, info=empty)
    private val vector1Ikm = Base64.getDecoder().decode("dGVzdF9pa21fZm9yX2VjZGhfc2hhcmVkX3NlY3JldF8=")
    private val vector1Out = Base64.getDecoder().decode("FEove+qkwyggpPKD5JDW3N3JH82aZzIogMbmMQ6QpZc=")

    private val vector2Ikm = Base64.getDecoder().decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
    private val vector2Out = Base64.getDecoder().decode("N60pEJ9DJlKHgEtnTiZT0KUTcYkH+X/Kl8lb3tgQS78=")

    @Test
    fun `derive matches Python vector 1`() {
        val result = HkdfSha256.derive(vector1Ikm, salt = null, info = ByteArray(0), length = 32)
        assertArrayEquals(vector1Out, result)
    }

    @Test
    fun `derive matches Python vector 2`() {
        val result = HkdfSha256.derive(vector2Ikm, salt = null, info = ByteArray(0), length = 32)
        assertArrayEquals(vector2Out, result)
    }

    @Test
    fun `derive with explicit salt differs from null salt`() {
        val ikm = ByteArray(32) { it.toByte() }
        val r1 = HkdfSha256.derive(ikm, salt = null)
        val r2 = HkdfSha256.derive(ikm, salt = ByteArray(16) { 1 })
        assert(!r1.contentEquals(r2))
    }

    @Test
    fun `derive with same inputs is deterministic`() {
        val ikm = ByteArray(32) { 42 }
        val r1 = HkdfSha256.derive(ikm)
        val r2 = HkdfSha256.derive(ikm)
        assertArrayEquals(r1, r2)
    }

    @Test
    fun `derive longer output works`() {
        val ikm = ByteArray(32) { it.toByte() }
        val result = HkdfSha256.derive(ikm, length = 64)
        assert(result.size == 64)
        // First 32 bytes must equal length=32 output
        val short = HkdfSha256.derive(ikm, length = 32)
        assertArrayEquals(short, result.copyOf(32))
    }
}
