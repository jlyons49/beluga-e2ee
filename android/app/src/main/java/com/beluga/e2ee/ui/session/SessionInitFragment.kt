package com.beluga.e2ee.ui.session

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.beluga.e2ee.BelugaApplication
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentSessionInitBinding
import com.beluga.e2ee.protocol.QrMessageParser
import com.beluga.e2ee.protocol.model.QrMessage
import com.beluga.e2ee.qr.QrEncoder
import com.beluga.e2ee.qr.QrScannerHelper
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SessionInitFragment : Fragment() {

    private var _binding: FragmentSessionInitBinding? = null
    private val binding get() = _binding!!
    private val args: SessionInitFragmentArgs by navArgs()
    private val viewModel: SessionViewModel by viewModels()
    private var scanner: QrScannerHelper? = null
    private var ownQrJson: String? = null

    private val requestPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> if (granted) startScanner() }

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
        _binding = FragmentSessionInitBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.state.observe(viewLifecycleOwner) { state ->
            when (state) {
                is SessionViewModel.State.ShowQr -> {
                    ownQrJson = state.qrJson
                    viewModel.clearState()
                    binding.ivQrCode.setImageBitmap(QrEncoder.encode(state.qrJson))
                    binding.ivQrCode.visibility = View.VISIBLE
                    binding.tvInstruction.setText(R.string.session_show_qr)
                    binding.btnScanReply.visibility = View.VISIBLE
                    binding.btnPickImage.visibility = View.VISIBLE
                }
                is SessionViewModel.State.Error -> {
                    viewModel.clearState()
                    Snackbar.make(view, state.message, Snackbar.LENGTH_LONG).show()
                }
                is SessionViewModel.State.Success -> viewModel.clearState()
                null -> {}
            }
        }

        binding.btnScanReply.setOnClickListener {
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

        binding.btnDone.setOnClickListener {
            findNavController().popBackStack()
        }

        viewModel.initSession(args.userId)
    }

    private fun startScanner() {
        binding.previewView.visibility = View.VISIBLE
        binding.btnScanReply.visibility = View.GONE
        binding.btnPickImage.visibility = View.GONE
        scanner = QrScannerHelper(
            context = requireContext(),
            lifecycleOwner = viewLifecycleOwner,
            previewView = binding.previewView,
            onResult = { raw -> handleScanResult(raw) }
        )
        scanner?.start()
    }

    private fun handleScanResult(raw: String) {
        val app = requireActivity().application as BelugaApplication
        try {
            val msg = QrMessageParser.parse(raw) as? QrMessage.SessionInit ?: run {
                Snackbar.make(requireView(), "Expected a session-init QR", Snackbar.LENGTH_SHORT).show()
                scanner?.reset()
                return
            }
            CoroutineScope(Dispatchers.Main).launch {
                val reply = app.e2eSystem?.acceptSessionInit(args.userId, msg)
                if (reply != null) {
                    val payloads = arrayOf(reply)
                    findNavController().navigate(
                        SessionInitFragmentDirections.actionSessionToQrDisplay(payloads)
                    )
                } else {
                    scanner?.stop()
                    binding.previewView.visibility = View.GONE
                    binding.ivQrCode.setImageBitmap(QrEncoder.encode(ownQrJson!!))
                    binding.ivQrCode.visibility = View.VISIBLE
                    binding.tvInstruction.setText(R.string.session_waiting_peer)
                    binding.btnDone.visibility = View.VISIBLE
                }
            }
        } catch (e: Exception) {
            Snackbar.make(requireView(), "Invalid QR: ${e.message}", Snackbar.LENGTH_LONG).show()
            scanner?.reset()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        scanner?.stop()
        _binding = null
    }
}
