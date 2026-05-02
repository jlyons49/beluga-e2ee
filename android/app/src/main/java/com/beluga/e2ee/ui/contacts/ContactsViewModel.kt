package com.beluga.e2ee.ui.contacts

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.beluga.e2ee.BelugaApplication
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class ContactsViewModel(app: Application) : AndroidViewModel(app) {

    private val repo get() = getApplication<BelugaApplication>().databaseRepository

    private val _contacts = MutableLiveData<List<String>>()
    val contacts: LiveData<List<String>> = _contacts

    fun load() {
        viewModelScope.launch(Dispatchers.IO) {
            _contacts.postValue(repo.getAllContactIds())
        }
    }

    fun deleteContact(userId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            repo.removePublicKey(userId)
            _contacts.postValue(repo.getAllContactIds())
        }
    }
}
