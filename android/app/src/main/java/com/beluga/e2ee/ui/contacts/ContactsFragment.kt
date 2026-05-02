package com.beluga.e2ee.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.beluga.e2ee.R
import com.beluga.e2ee.databinding.FragmentContactsBinding
import com.beluga.e2ee.databinding.ItemContactBinding

class ContactsFragment : Fragment() {

    private var _binding: FragmentContactsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ContactsViewModel by viewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentContactsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val adapter = ContactAdapter(
            onTap = { userId ->
                findNavController().navigate(
                    ContactsFragmentDirections.actionContactsToSession(userId)
                )
            },
            onLongPress = { userId ->
                AlertDialog.Builder(requireContext())
                    .setMessage(getString(R.string.contacts_delete_confirm))
                    .setPositiveButton(R.string.btn_ok) { _, _ -> viewModel.deleteContact(userId) }
                    .setNegativeButton(R.string.btn_cancel, null)
                    .show()
            }
        )
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter
        binding.fabAddContact.setOnClickListener {
            findNavController().navigate(R.id.action_contacts_to_addContact)
        }
        viewModel.contacts.observe(viewLifecycleOwner) { list ->
            adapter.submitList(list)
            binding.tvEmpty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        }
        viewModel.load()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

private class ContactAdapter(
    private val onTap: (String) -> Unit,
    private val onLongPress: (String) -> Unit
) : RecyclerView.Adapter<ContactAdapter.VH>() {

    private var items = listOf<String>()

    fun submitList(list: List<String>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemContactBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(binding)
    }

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(items[position])
    override fun getItemCount() = items.size

    inner class VH(private val b: ItemContactBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(userId: String) {
            b.tvContactId.text = userId
            b.root.setOnClickListener { onTap(userId) }
            b.root.setOnLongClickListener { onLongPress(userId); true }
        }
    }
}
