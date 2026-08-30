package dev.caturma.testauthenticator

import java.io.ByteArrayOutputStream

/* Enough CBOR to write an attestation object and a COSE key, and not one
   byte more.
 *
 * A writer only, deliberately. Nothing here ever reads CBOR: the relying
 * party parses what this produces, and a reader would be a second
 * implementation of a format this file only has to agree with once.
 *
 * Canonical ordering is the caller's job -- `map` writes pairs in the order
 * given. COSE keys are the one place that matters and Cose.p256 below is
 * written in the order RFC 8152 wants. */
object Cbor {

  private fun head(out: ByteArrayOutputStream, major: Int, value: Long) {
    val m = major shl 5
    when {
      value < 24 -> out.write(m or value.toInt())
      value < 0x100 -> { out.write(m or 24); out.write(value.toInt()) }
      value < 0x10000 -> {
        out.write(m or 25)
        out.write((value shr 8).toInt() and 0xff); out.write(value.toInt() and 0xff)
      }
      value < 0x100000000L -> {
        out.write(m or 26)
        for (s in intArrayOf(24, 16, 8, 0)) out.write((value shr s).toInt() and 0xff)
      }
      else -> {
        out.write(m or 27)
        for (s in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) out.write((value shr s).toInt() and 0xff)
      }
    }
  }

  fun uint(v: Long): ByteArray =
    ByteArrayOutputStream().also { head(it, 0, v) }.toByteArray()

  /* Negative integers are major type 1, encoded as -1 - n. COSE key labels
     use them (-1 is the curve, -2 and -3 the coordinates), which is the
     only reason this exists. */
  fun nint(v: Long): ByteArray =
    ByteArrayOutputStream().also { head(it, 1, -1 - v) }.toByteArray()

  fun bytes(b: ByteArray): ByteArray =
    ByteArrayOutputStream().also { head(it, 2, b.size.toLong()); it.write(b) }.toByteArray()

  fun text(s: String): ByteArray {
    val b = s.toByteArray(Charsets.UTF_8)
    return ByteArrayOutputStream().also { head(it, 3, b.size.toLong()); it.write(b) }.toByteArray()
  }

  /* Pairs already encoded, so a caller can mix key types -- an attestation
     object is keyed by text, a COSE key by integers. */
  fun map(pairs: List<Pair<ByteArray, ByteArray>>): ByteArray {
    val out = ByteArrayOutputStream()
    head(out, 5, pairs.size.toLong())
    for ((k, v) in pairs) { out.write(k); out.write(v) }
    return out.toByteArray()
  }
}
