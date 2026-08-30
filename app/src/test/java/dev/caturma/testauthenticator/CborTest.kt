package dev.caturma.testauthenticator

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/* The encoder, against the examples in RFC 8949 appendix A.
 *
 * These are not chosen for coverage, they are chosen because a relying
 * party reads this and nothing else says whether it is right. The negative
 * integers matter most: every label in a COSE key below -1 is one, and
 * getting them wrong produces bytes that still parse as *something*. */
class CborTest {

  private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

  @Test fun `unsigned integers`() {
    assertEquals("00", hex(Cbor.uint(0)))
    assertEquals("17", hex(Cbor.uint(23)))
    assertEquals("1818", hex(Cbor.uint(24)))
    assertEquals("1901f4", hex(Cbor.uint(500)))
  }

  /* RFC 8949: major type 1 encodes -1-n, so -1 is 0x20 and -7 is 0x26.
     The call sites pass the actual negative number; anything else is a
     unit mismatch waiting to be discovered on a server. */
  @Test fun `negative integers are the number, not the argument`() {
    assertEquals("20", hex(Cbor.nint(-1)))
    assertEquals("21", hex(Cbor.nint(-2)))
    assertEquals("22", hex(Cbor.nint(-3)))
    assertEquals("26", hex(Cbor.nint(-7)))
  }

  @Test fun `byte and text strings`() {
    assertEquals("43010203", hex(Cbor.bytes(byteArrayOf(1, 2, 3))))
    assertEquals("63666d74", hex(Cbor.text("fmt")))
    assertEquals("40", hex(Cbor.bytes(ByteArray(0))))
  }

  @Test fun `an empty map is a single byte`() {
    assertArrayEquals(byteArrayOf(0xa0.toByte()), Cbor.map(emptyList()))
  }

  @Test fun `a map counts its pairs, not its bytes`() {
    val m = Cbor.map(listOf(Cbor.uint(1) to Cbor.uint(2), Cbor.uint(3) to Cbor.nint(-7)))
    assertEquals("a2010203" + "26", hex(m))
  }
}
