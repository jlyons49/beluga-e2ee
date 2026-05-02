package com.beluga.e2ee.ui.receive

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentReceiveBinding
import com.beluga.e2ee.qr.QrScannerHelper
import com.google.android.material.snackbar.Snackbar

class ReceiveFragment : Fragment() {

    private var _binding: FragmentReceiveBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ReceiveViewModel by viewModels()
    private var scanner: QrScannerHelper? = null

    private val requestPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) startScanner()
        else Snackbar.make(requireView(), "Camera permission required", Snackbar.LENGTH_LONG).show()
    }

    private val pickImage = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri ?: return@registerForActivityResult
        val userId = binding.spinnerContact.selectedItem?.toString() ?: ""
        if (userId.isBlank()) {
            Snackbar.make(requireView(), "No contact selected", Snackbar.LENGTH_SHORT).show()
            return@registerForActivityResult
        }
        QrScannerHelper.scanFromUri(
            context = requireContext(),
            uri = uri,
            onResult = { raw -> viewModel.handleQr(userId, raw) },
            onFailure = { Snackbar.make(requireView(), R.string.pick_no_qr, Snackbar.LENGTH_SHORT).show() }
        )
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentReceiveBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.contacts.observe(viewLifecycleOwner) { contacts ->
            val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, contacts)
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            binding.spinnerContact.adapter = adapter
        }

        binding.btnStartScan.setOnClickListener {
            if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED) {
                startScanner()
            } else {
                requestPermission.launch(Manifest.permission.CAMERA)
            }
        }

        binding.btnPickImage.setOnClickListener {
            pickImage.launch("image/*")
        }

        viewModel.scanResult.observe(viewLifecycleOwner) { result ->
            result ?: return@observe
            viewModel.clearResult()
            when (result) {
                is ReceiveViewModel.ScanResult.Decrypted -> showMessage(result.text)
                is ReceiveViewModel.ScanResult.ChunkProgress ->
                    binding.tvStatus.text = "Chunk ${result.received} of ${result.total} received. Scan next."
                is ReceiveViewModel.ScanResult.SessionReply -> {
                    val payloads = arrayOf(result.replyQrJson)
                    findNavController().navigate(
                        ReceiveFragmentDirections.actionReceiveToQrDisplay(payloads)
                    )
                }
                is ReceiveViewModel.ScanResult.SessionDone ->
                    Snackbar.make(requireView(), R.string.session_success, Snackbar.LENGTH_SHORT).show()
                is ReceiveViewModel.ScanResult.KeyStored ->
                    Snackbar.make(requireView(), "Public key stored.", Snackbar.LENGTH_SHORT).show()
                is ReceiveViewModel.ScanResult.Error ->
                    Snackbar.make(requireView(), result.msg, Snackbar.LENGTH_LONG).show()
            }
        }

        viewModel.loadContacts()
    }

    private fun startScanner() {
        val userId = binding.spinnerContact.selectedItem?.toString() ?: ""
        if (userId.isBlank()) {
            Snackbar.make(requireView(), "No contact selected", Snackbar.LENGTH_SHORT).show()
            return
        }
        binding.previewView.visibility = View.VISIBLE
        binding.btnStartScan.isEnabled = false
        binding.btnPickImage.isEnabled = false
        scanner = QrScannerHelper(
            context = requireContext(),
            lifecycleOwner = viewLifecycleOwner,
            previewView = binding.previewView,
            onResult = { raw -> viewModel.handleQr(userId, raw) }
        )
        scanner?.start()
    }

    private fun showMessage(plaintext: String) {
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.receive_decrypted_title)
            .setMessage(plaintext)
            .setPositiveButton(R.string.btn_ok) { _, _ -> scanner?.reset() }
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        scanner?.stop()
        _binding = null
    }
}
