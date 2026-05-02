package com.beluga.e2ee.ui.sharekey

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.beluga.e2ee.BelugaApplication
import com.beluga.e2ee.databinding.FragmentShareKeyBinding
import com.beluga.e2ee.qr.QrEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ShareKeyFragment : Fragment() {

    private var _binding: FragmentShareKeyBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentShareKeyBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val app = requireActivity().application as BelugaApplication
        viewLifecycleOwner.lifecycleScope.launch {
            val qrJson = withContext(Dispatchers.IO) {
                app.e2eSystem?.sharePublicKey()
            } ?: return@launch
            binding.ivQrCode.setImageBitmap(QrEncoder.encode(qrJson))
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
