package com.beluga.e2ee.ui.send

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.beluga.e2ee.BelugaApplication
import kotlinx.coroutines.launch

class SendMessageViewModel(app: Application) : AndroidViewModel(app) {

    private val repo get() = getApplication<BelugaApplication>().databaseRepository
    private val system get() = getApplication<BelugaApplication>().e2eSystem

    private val _contacts = MutableLiveData<List<String>>()
    val contacts: LiveData<List<String>> = _contacts

    sealed class Result {
        data class Ready(val payloads: List<String>) : Result()
        data class Error(val message: String) : Result()
    }

    private val _result = MutableLiveData<Result?>()
    val result: LiveData<Result?> = _result

    fun loadContacts() {
        viewModelScope.launch {
            _contacts.postValue(repo.getAllContactIds())
        }
    }

    fun encrypt(userId: String, message: String) {
        viewModelScope.launch {
            try {
                val payloads = system?.sendEncryptedMessage(userId, message)
                    ?: run { _result.postValue(Result.Error("Not unlocked")); return@launch }
                _result.postValue(Result.Ready(payloads))
            } catch (e: NoSuchElementException) {
                _result.postValue(Result.Error("No active session for '$userId'. Init session first."))
            }
        }
    }

    fun clearResult() { _result.value = null }
}
