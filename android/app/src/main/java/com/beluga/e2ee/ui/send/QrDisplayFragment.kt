package com.beluga.e2ee.ui.send

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.navArgs
import com.beluga.e2ee.databinding.FragmentQrDisplayBinding
import com.beluga.e2ee.qr.QrEncoder

class QrDisplayFragment : Fragment() {

    private var _binding: FragmentQrDisplayBinding? = null
    private val binding get() = _binding!!
    private val args: QrDisplayFragmentArgs by navArgs()
    private var currentIndex = 0

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentQrDisplayBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val payloads = args.qrPayloads
        updateDisplay(payloads)

        binding.btnPrev.setOnClickListener {
            if (currentIndex > 0) { currentIndex--; updateDisplay(payloads) }
        }
        binding.btnNext.setOnClickListener {
            if (currentIndex < payloads.size - 1) { currentIndex++; updateDisplay(payloads) }
        }
    }

    private fun updateDisplay(payloads: Array<String>) {
        val total = payloads.size
        val bitmap = QrEncoder.encode(payloads[currentIndex])
        binding.ivQrCode.setImageBitmap(bitmap)
        binding.tvCounter.text = if (total > 1) "QR ${currentIndex + 1} of $total" else ""
        binding.btnPrev.visibility = if (total > 1 && currentIndex > 0) View.VISIBLE else View.INVISIBLE
        binding.btnNext.visibility = if (total > 1 && currentIndex < total - 1) View.VISIBLE else View.INVISIBLE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
