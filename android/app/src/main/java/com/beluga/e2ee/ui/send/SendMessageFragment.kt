package com.beluga.e2ee.ui.send

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentSendMessageBinding
import com.google.android.material.snackbar.Snackbar

class SendMessageFragment : Fragment() {

    private var _binding: FragmentSendMessageBinding? = null
    private val binding get() = _binding!!
    private val viewModel: SendMessageViewModel by viewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentSendMessageBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.contacts.observe(viewLifecycleOwner) { contacts ->
            val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_spinner_item, contacts)
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            binding.spinnerContact.adapter = adapter
        }

        binding.btnEncrypt.setOnClickListener {
            val userId = binding.spinnerContact.selectedItem?.toString() ?: ""
            val message = binding.etMessage.text?.toString() ?: ""
            if (userId.isBlank()) {
                Snackbar.make(view, "No contact selected", Snackbar.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (message.isBlank()) {
                Snackbar.make(view, "Message is empty", Snackbar.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            viewModel.encrypt(userId, message)
        }

        viewModel.result.observe(viewLifecycleOwner) { result ->
            when (result) {
                is SendMessageViewModel.Result.Ready -> {
                    viewModel.clearResult()
                    val payloads = result.payloads.toTypedArray()
                    val action = SendMessageFragmentDirections.actionSendToQrDisplay(payloads)
                    findNavController().navigate(action)
                }
                is SendMessageViewModel.Result.Error -> {
                    viewModel.clearResult()
                    Snackbar.make(view, result.message, Snackbar.LENGTH_LONG).show()
                }
                null -> {}
            }
        }

        viewModel.loadContacts()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
