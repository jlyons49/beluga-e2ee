package com.beluga.e2ee.ui.unlock

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.beluga.e2ee.BelugaApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class UnlockViewModel(app: Application) : AndroidViewModel(app) {

    sealed class State {
        object Idle : State()
        object Loading : State()
        object Success : State()
        object WrongPassword : State()
    }

    private val _state = MutableLiveData<State>(State.Idle)
    val state: LiveData<State> = _state

    fun unlock(password: String) {
        if (password.isBlank()) return
        _state.value = State.Loading
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<BelugaApplication>()
            val ok = app.databaseRepository.unlock(password)
            if (ok) {
                app.onUnlocked()
                app.e2eSystem?.initialize()
            }
            _state.postValue(if (ok) State.Success else State.WrongPassword)
        }
    }
}
