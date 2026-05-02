package com.beluga.e2ee.protocol

import com.beluga.e2ee.protocol.model.QrMessage
import org.json.JSONObject

/**
 * Serializes and parses QR message JSON payloads.
 * Wire format is byte-for-byte compatible with the Python beluga client.
 */
object QrMessageParser {

    fun parse(raw: String): QrMessage {
        val json = JSONObject(raw)
        return when (val mode = json.getInt("mode")) {
            1 -> QrMessage.SingleChunk(
                iv  = json.getString("iv"),
                ct  = json.getString("ct"),
                tag = json.getString("tag")
            )
            2 -> QrMessage.MultiChunk(
                index = json.getInt("index"),
                total = json.getInt("total"),
                iv    = json.getString("iv"),
                ct    = json.getString("ct"),
                tag   = json.getString("tag")
            )
            3 -> QrMessage.SessionInit(
                sec = json.getString("sec"),
                sig = json.getString("sig")
            )
            6 -> QrMessage.SharePublicKey(
                publickey = json.getString("publickey")
            )
            else -> throw IllegalArgumentException("Unknown QR message mode: $mode")
        }
    }

    fun serialize(msg: QrMessage): String = when (msg) {
        is QrMessage.SingleChunk -> JSONObject().apply {
            put("mode", 1)
            put("iv", msg.iv)
            put("ct", msg.ct)
            put("tag", msg.tag)
        }.toString()

        is QrMessage.MultiChunk -> JSONObject().apply {
            put("mode", 2)
            put("index", msg.index)
            put("total", msg.total)
            put("iv", msg.iv)
            put("ct", msg.ct)
            put("tag", msg.tag)
        }.toString()

        is QrMessage.SessionInit -> JSONObject().apply {
            put("mode", 3)
            put("sec", msg.sec)
            put("sig", msg.sig)
        }.toString()

        is QrMessage.SharePublicKey -> JSONObject().apply {
            put("mode", 6)
            put("publickey", msg.publickey)
        }.toString()
    }
}
