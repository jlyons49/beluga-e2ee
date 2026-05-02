package com.beluga.e2ee.ui.unlock

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentUnlockBinding
import com.google.android.material.snackbar.Snackbar

class UnlockFragment : Fragment() {

    private var _binding: FragmentUnlockBinding? = null
    private val binding get() = _binding!!
    private val viewModel: UnlockViewModel by viewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentUnlockBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnUnlock.setOnClickListener {
            viewModel.unlock(binding.etPassword.text?.toString() ?: "")
        }

        viewModel.state.observe(viewLifecycleOwner) { state ->
            when (state) {
                is UnlockViewModel.State.Loading -> binding.btnUnlock.isEnabled = false
                is UnlockViewModel.State.Success -> findNavController().navigate(R.id.action_unlock_to_home)
                is UnlockViewModel.State.WrongPassword -> {
                    binding.btnUnlock.isEnabled = true
                    Snackbar.make(view, R.string.unlock_wrong_password, Snackbar.LENGTH_SHORT).show()
                }
                is UnlockViewModel.State.Idle -> binding.btnUnlock.isEnabled = true
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
