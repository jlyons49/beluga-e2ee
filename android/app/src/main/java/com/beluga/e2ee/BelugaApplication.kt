package com.beluga.e2ee

import android.app.Application
import com.beluga.e2ee.protocol.E2eSystem
import com.beluga.e2ee.storage.DatabaseRepository
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class BelugaApplication : Application() {

    lateinit var databaseRepository: DatabaseRepository
        private set

    var e2eSystem: E2eSystem? = null
        private set

    override fun onCreate() {
        super.onCreate()
        // Replace Android's limited BouncyCastle with the full provider.
        // Must happen before any crypto operations.
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
        databaseRepository = DatabaseRepository(this)
    }

    fun onUnlocked() {
        e2eSystem = E2eSystem(databaseRepository)
    }

    fun lock() {
        e2eSystem = null
        databaseRepository.lock()
    }
}
