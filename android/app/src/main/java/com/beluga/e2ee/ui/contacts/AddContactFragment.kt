package com.beluga.e2ee.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.beluga.e2ee.BelugaApplication
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentAddContactBinding
import com.beluga.e2ee.protocol.QrMessageParser
import com.beluga.e2ee.protocol.model.QrMessage
import com.beluga.e2ee.qr.QrScannerHelper
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class AddContactFragment : Fragment() {

    private var _binding: FragmentAddContactBinding? = null
    private val binding get() = _binding!!
    private var scanner: QrScannerHelper? = null

    private val pickImage = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri ?: return@registerForActivityResult
        QrScannerHelper.scanFromUri(
            context = requireContext(),
            uri = uri,
            onResult = { raw -> handleScanResult(raw) },
            onFailure = { Snackbar.make(requireView(), R.string.pick_no_qr, Snackbar.LENGTH_SHORT).show() }
        )
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAddContactBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.btnScanPublicKey.setOnClickListener { startScanner() }
        binding.btnPickImage.setOnClickListener { pickImage.launch("image/*") }
    }

    private fun startScanner() {
        binding.previewView.visibility = View.VISIBLE
        binding.btnScanPublicKey.isEnabled = false
        binding.btnPickImage.isEnabled = false
        scanner = QrScannerHelper(
            context = requireContext(),
            lifecycleOwner = viewLifecycleOwner,
            previewView = binding.previewView,
            onResult = { raw -> handleScanResult(raw) }
        )
        scanner?.start()
    }

    private fun handleScanResult(raw: String) {
        val userId = binding.etContactId.text?.toString()?.trim() ?: ""
        if (userId.isBlank()) {
            Snackbar.make(requireView(), R.string.add_contact_id_hint, Snackbar.LENGTH_SHORT).show()
            scanner?.reset()
            return
        }
        val app = requireActivity().application as BelugaApplication
        try {
            val msg = QrMessageParser.parse(raw)
            if (msg is QrMessage.SharePublicKey) {
                CoroutineScope(Dispatchers.Main).launch {
                    app.e2eSystem?.receivePublicKey(userId, msg)
                    findNavController().popBackStack()
                }
            } else {
                Snackbar.make(requireView(), "Expected a public key QR (mode 6)", Snackbar.LENGTH_SHORT).show()
                scanner?.reset()
            }
        } catch (e: Exception) {
            Snackbar.make(requireView(), "Invalid QR code", Snackbar.LENGTH_SHORT).show()
            scanner?.reset()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        scanner?.stop()
        _binding = null
    }
}
