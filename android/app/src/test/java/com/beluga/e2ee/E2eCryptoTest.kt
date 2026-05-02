package com.beluga.e2ee

import com.beluga.e2ee.crypto.E2eCrypto
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.Security
import javax.crypto.AEADBadTagException

class E2eCryptoTest {

    @Before
    fun setUp() {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    // --- Encrypt / Decrypt ---

    @Test
    fun `encrypt then decrypt returns original`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val msg = "This is just a test".toByteArray(Charsets.US_ASCII)
        val result = E2eCrypto.encrypt(msg, key)
        val decrypted = E2eCrypto.decrypt(result.ciphertext, result.iv, result.tag, key)
        assertArrayEquals(msg, decrypted)
    }

    @Test
    fun `encrypt then decrypt long message`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val msg = ByteArray(32768) { ('A' + it % 26).code.toByte() }
        val result = E2eCrypto.encrypt(msg, key)
        assertFalse(result.ciphertext.contentEquals(msg))
        val decrypted = E2eCrypto.decrypt(result.ciphertext, result.iv, result.tag, key)
        assertArrayEquals(msg, decrypted)
    }

    @Test(expected = AEADBadTagException::class)
    fun `decrypt with wrong tag throws`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val msg = "test".toByteArray()
        val result = E2eCrypto.encrypt(msg, key)
        E2eCrypto.decrypt(result.ciphertext, result.iv, ByteArray(16), key)
    }

    @Test(expected = AEADBadTagException::class)
    fun `decrypt with wrong key throws`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val msg = "test".toByteArray()
        val result = E2eCrypto.encrypt(msg, key)
        E2eCrypto.decrypt(result.ciphertext, result.iv, result.tag, ByteArray(32))
    }

    // --- ECDSA Sign / Verify ---

    @Test
    fun `sign and verify succeeds`() {
        val pair = E2eCrypto.generateKeyPair()
        val data = ByteArray(1000) { it.toByte() }
        val sig = E2eCrypto.sign(data, pair.private)
        assertTrue(E2eCrypto.verify(data, sig, pair.public))
    }

    @Test
    fun `verify with wrong data returns false`() {
        val pair = E2eCrypto.generateKeyPair()
        val data = ByteArray(100) { it.toByte() }
        val sig = E2eCrypto.sign(data, pair.private)
        assertFalse(E2eCrypto.verify(ByteArray(100) { (it + 1).toByte() }, sig, pair.public))
    }

    @Test
    fun `verify with wrong key returns false`() {
        val pair1 = E2eCrypto.generateKeyPair()
        val pair2 = E2eCrypto.generateKeyPair()
        val data = ByteArray(50) { it.toByte() }
        val sig = E2eCrypto.sign(data, pair1.private)
        assertFalse(E2eCrypto.verify(data, sig, pair2.public))
    }

    // --- ECDH ---

    @Test
    fun `ECDH produces same shared key on both sides`() {
        val pair1 = E2eCrypto.generateKeyPair()
        val pair2 = E2eCrypto.generateKeyPair()
        val key1 = E2eCrypto.performEcdh(pair1.private, pair2.public)
        val key2 = E2eCrypto.performEcdh(pair2.private, pair1.public)
        assertArrayEquals(key1, key2)
        assertEquals(32, key1.size)
    }

    @Test
    fun `ECDH with different keys produces different secrets`() {
        val pair1 = E2eCrypto.generateKeyPair()
        val pair2 = E2eCrypto.generateKeyPair()
        val pair3 = E2eCrypto.generateKeyPair()
        val key1 = E2eCrypto.performEcdh(pair1.private, pair2.public)
        val key2 = E2eCrypto.performEcdh(pair1.private, pair3.public)
        assertFalse(key1.contentEquals(key2))
    }

    // --- Key serialization ---

    @Test
    fun `public key to bytes and back roundtrips`() {
        val pair = E2eCrypto.generateKeyPair()
        val bytes = E2eCrypto.publicKeyToBytes(pair.public)
        assertEquals(49, bytes.size) // P-384 compressed point = 1 + 48 bytes
        val restored = E2eCrypto.bytesToPublicKey(bytes)
        assertArrayEquals(bytes, E2eCrypto.publicKeyToBytes(restored))
    }

    @Test
    fun `private key to base64 and back roundtrips`() {
        val pair = E2eCrypto.generateKeyPair()
        val b64 = E2eCrypto.privateKeyToBase64(pair.private)
        val restored = E2eCrypto.base64ToPrivateKey(b64)
        // Verify keys are equivalent by signing and verifying
        val data = "verify-after-restore".toByteArray()
        val sig = E2eCrypto.sign(data, restored)
        assertTrue(E2eCrypto.verify(data, sig, pair.public))
    }

    @Test
    fun `restored public key works for ECDH`() {
        val pair1 = E2eCrypto.generateKeyPair()
        val pair2 = E2eCrypto.generateKeyPair()
        val pubBytes = E2eCrypto.publicKeyToBytes(pair2.public)
        val restoredPub = E2eCrypto.bytesToPublicKey(pubBytes)
        val k1 = E2eCrypto.performEcdh(pair1.private, pair2.public)
        val k2 = E2eCrypto.performEcdh(pair1.private, restoredPub)
        assertArrayEquals(k1, k2)
    }

    @Test
    fun `encrypt IV is always 16 bytes`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val result = E2eCrypto.encrypt("test".toByteArray(), key)
        assertEquals(16, result.iv.size)
    }

    @Test
    fun `encrypt tag is always 16 bytes`() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val result = E2eCrypto.encrypt("test".toByteArray(), key)
        assertEquals(16, result.tag.size)
    }
}
