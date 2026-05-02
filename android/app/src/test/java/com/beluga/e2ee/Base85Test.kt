package com.beluga.e2ee

import com.beluga.e2ee.crypto.Base85
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class Base85Test {

    // Vectors from Python: base64.b85encode(input).decode()
    private val vectors = listOf(
        ByteArray(0)            to "",
        byteArrayOf(0x68)       to "Xa",
        byteArrayOf(0x68, 0x65) to "Xk`",
        "hel".toByteArray()     to "Xk}~",
        "hell".toByteArray()    to "Xk~0{",
        "hello".toByteArray()   to "Xk~0{Zv",
        "Hello World!".toByteArray() to "NM&qnZy;B1a%^NF",
        ByteArray(16) { it.toByte() } to "009C61O)~M2nh-c3=Iws",
        ByteArray(32) { it.toByte() } to "009C61O)~M2nh-c3=Iws5D^j+6crX17#SKH9337X"
    )

    @Test
    fun `encode matches Python vectors`() {
        vectors.forEach { (input, expected) ->
            assertEquals("encode(${input.size} bytes)", expected, Base85.encode(input))
        }
    }

    @Test
    fun `decode matches Python vectors`() {
        vectors.forEach { (expected, encoded) ->
            assertArrayEquals("decode('$encoded')", expected, Base85.decode(encoded))
        }
    }

    @Test
    fun `roundtrip for random-ish data`() {
        val data = ByteArray(97) { (it * 37 + 13).toByte() }
        assertArrayEquals(data, Base85.decode(Base85.encode(data)))
    }

    @Test
    fun `roundtrip for all zero bytes`() {
        val data = ByteArray(20)
        assertArrayEquals(data, Base85.decode(Base85.encode(data)))
    }

    @Test
    fun `roundtrip for all 0xFF bytes`() {
        val data = ByteArray(20) { 0xFF.toByte() }
        assertArrayEquals(data, Base85.decode(Base85.encode(data)))
    }

    @Test
    fun `empty roundtrip`() {
        assertArrayEquals(ByteArray(0), Base85.decode(Base85.encode(ByteArray(0))))
    }

    @Test
    fun `output length formula`() {
        for (n in 0..20) {
            val data = ByteArray(n)
            val encoded = Base85.encode(data)
            val expectedLen = if (n == 0) 0 else (n * 5 + 3) / 4
            assertEquals("encode length for n=$n", expectedLen, encoded.length)
        }
    }
}
