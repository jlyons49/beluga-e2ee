package com.beluga.e2ee

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.beluga.e2ee.storage.DatabaseRepository
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import java.security.Security

@RunWith(AndroidJUnit4::class)
class DatabaseRepositoryTest {

    private lateinit var repo: DatabaseRepository
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
        // Clean up any existing database
        File(context.filesDir, "database.bin").delete()
        repo = DatabaseRepository(context)
    }

    @After
    fun tearDown() {
        repo.lock()
        File(context.filesDir, "database.bin").delete()
    }

    @Test
    fun unlockFirstRunSucceeds() {
        assertTrue(repo.unlock("mypassword"))
        assertTrue(repo.isUnlocked)
    }

    @Test
    fun unlockWrongPasswordReturnsFalse() {
        assertTrue(repo.unlock("correct"))
        repo.saveSessionKey("test", ByteArray(32))
        repo.lock()
        assertFalse(repo.unlock("wrong"))
    }

    @Test
    fun saveAndLoadSessionKey() {
        repo.unlock("password")
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        repo.saveSessionKey("alice", key)
        assertArrayEquals(key, repo.getSessionKey("alice"))
        repo.removeSession("alice")
        assertFalse(repo.hasSession("alice"))
    }

    @Test(expected = NoSuchElementException::class)
    fun getAbsentSessionKeyThrows() {
        repo.unlock("password")
        repo.getSessionKey("nobody")
    }

    @Test
    fun saveAndLoadSigningKey() {
        repo.unlock("password")
        assertFalse(repo.hasSigningKey())
        repo.setSigningKey("fakePKCS8base64==")
        assertEquals("fakePKCS8base64==", repo.getSigningKey())
    }

    @Test
    fun saveAndLoadPublicKey() {
        repo.unlock("password")
        val bytes = ByteArray(49).also { SecureRandom().nextBytes(it) }
        repo.storePublicKey("bob", bytes)
        assertArrayEquals(bytes, repo.getPublicKey("bob"))
        assertEquals(listOf("bob"), repo.getAllContactIds())
        repo.removePublicKey("bob")
        assertTrue(repo.getAllContactIds().isEmpty())
    }

    @Test
    fun dataPersistedAcrossUnlock() {
        repo.unlock("password")
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        repo.saveSessionKey("carol", key)
        repo.lock()

        val repo2 = DatabaseRepository(context)
        assertTrue(repo2.unlock("password"))
        assertArrayEquals(key, repo2.getSessionKey("carol"))
    }
}
