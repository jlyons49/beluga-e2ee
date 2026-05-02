package com.beluga.e2ee.ui.receive

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.beluga.e2ee.BelugaApplication
import com.beluga.e2ee.protocol.QrMessageParser
import com.beluga.e2ee.protocol.model.QrMessage
import kotlinx.coroutines.launch

class ReceiveViewModel(app: Application) : AndroidViewModel(app) {

    private val repo get() = getApplication<BelugaApplication>().databaseRepository

    private val _contacts = MutableLiveData<List<String>>()
    val contacts: LiveData<List<String>> = _contacts

    fun loadContacts() {
        viewModelScope.launch { _contacts.postValue(repo.getAllContactIds()) }
    }

    sealed class ScanResult {
        data class Decrypted(val text: String) : ScanResult()
        data class ChunkProgress(val received: Int, val total: Int) : ScanResult()
        data class SessionReply(val replyQrJson: String) : ScanResult()
        object SessionDone : ScanResult()
        object KeyStored : ScanResult()
        data class Error(val msg: String) : ScanResult()
    }

    private val _scanResult = MutableLiveData<ScanResult?>()
    val scanResult: LiveData<ScanResult?> = _scanResult

    fun handleQr(userId: String, raw: String) {
        val system = getApplication<BelugaApplication>().e2eSystem ?: return
        viewModelScope.launch {
            try {
                val msg = QrMessageParser.parse(raw)
                when (msg) {
                    is QrMessage.SingleChunk -> {
                        val plaintext = system.receiveMessage(userId, msg)
                        if (plaintext != null) _scanResult.postValue(ScanResult.Decrypted(plaintext))
                    }
                    is QrMessage.MultiChunk -> {
                        _scanResult.postValue(ScanResult.ChunkProgress(msg.index + 1, msg.total))
                        val plaintext = system.receiveMessage(userId, msg)
                        if (plaintext != null) _scanResult.postValue(ScanResult.Decrypted(plaintext))
                    }
                    is QrMessage.SessionInit -> {
                        val reply = system.acceptSessionInit(userId, msg)
                        _scanResult.postValue(
                            if (reply != null) ScanResult.SessionReply(reply)
                            else ScanResult.SessionDone
                        )
                    }
                    is QrMessage.SharePublicKey -> {
                        system.receivePublicKey(userId, msg)
                        _scanResult.postValue(ScanResult.KeyStored)
                    }
                }
            } catch (e: Exception) {
                _scanResult.postValue(ScanResult.Error(e.message ?: "Unknown error"))
            }
        }
    }

    fun clearResult() { _scanResult.value = null }
}
