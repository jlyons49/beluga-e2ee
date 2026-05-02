package com.beluga.e2ee.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.navigation.fragment.findNavController
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentHomeBinding

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnReceive.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_receive)
        }
        binding.btnSend.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_send)
        }
        binding.btnSession.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_contacts_for_session)
        }
        binding.btnShareKey.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_sharekey)
        }
        binding.fabContacts.setOnClickListener {
            findNavController().navigate(R.id.action_home_to_contacts)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
