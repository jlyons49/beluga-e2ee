package com.beluga.e2ee.ui.session

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.beluga.e2ee.BelugaApplication
import kotlinx.coroutines.launch

class SessionViewModel(app: Application) : AndroidViewModel(app) {

    sealed class State {
        data class ShowQr(val qrJson: String) : State()
        object Success : State()
        data class Error(val message: String) : State()
    }

    private val _state = MutableLiveData<State?>()
    val state: LiveData<State?> = _state

    fun initSession(userId: String) {
        val system = getApplication<BelugaApplication>().e2eSystem ?: return
        viewModelScope.launch {
            val qrJson = system.initializeSession(userId)
            if (qrJson != null) _state.postValue(State.ShowQr(qrJson))
            else _state.postValue(State.Error("No public key for '$userId'. Add them as a contact first."))
        }
    }

    fun clearState() { _state.value = null }
}
