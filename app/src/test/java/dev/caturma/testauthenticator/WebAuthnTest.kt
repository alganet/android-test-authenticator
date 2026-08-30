package dev.caturma.testauthenticator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/* The bytes a verifier reads, checked against what a verifier does.
 *
 * A plain JCE P-256 key stands in for the Keystore one: the public half is
 * the same object either way, and nothing here signs. */
class WebAuthnTest {

  private fun key(): ECPublicKey {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ECGenParameterSpec("secp256r1"))
    return g.generateKeyPair().public as ECPublicKey
  }

  private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

  /* A minimal reader, here and nowhere else. The encoder is not allowed one
     -- see Cbor.kt -- but a test that cannot read its own output is only
     asserting that the encoder is consistent with itself. */
  private fun readMap(b: ByteArray, start: Int = 0): Pair<Map<Long, Any>, Int> {
    var i = start
    require(b[i].toInt() and 0xe0 == 0xa0) { "not a map" }
    val n = b[i].toInt() and 0x1f
    i++
    val out = mutableMapOf<Long, Any>()
    repeat(n) {
      val (k, ki) = readItem(b, i); i = ki
      val (v, vi) = readItem(b, i); i = vi
      out[k as Long] = v
    }
    return out to i
  }

  private fun readItem(b: ByteArray, start: Int): Pair<Any, Int> {
    var i = start
    val major = (b[i].toInt() and 0xe0) shr 5
    val minor = b[i].toInt() and 0x1f
    i++
    var value = minor.toLong()
    if (minor == 24) { value = (b[i].toInt() and 0xff).toLong(); i++ }
    else if (minor == 25) { value = ((b[i].toInt() and 0xff) shl 8 or (b[i + 1].toInt() and 0xff)).toLong(); i += 2 }
    return when (major) {
      0 -> value to i
      1 -> (-1 - value) to i
      2 -> b.copyOfRange(i, i + value.toInt()) to (i + value.toInt())
      3 -> String(b, i, value.toInt(), Charsets.UTF_8) to (i + value.toInt())
      else -> error("unexpected major $major")
    }
  }

  @Test fun `the cose key uses the labels rfc 8152 gives`() {
    val (map, _) = readMap(WebAuthn.cosePublicKey(key()))
    assertEquals("kty is EC2", 2L, map[1])
    assertEquals("alg is ES256", -7L, map[3])
    assertEquals("crv is P-256", 1L, map[-1])
    assertTrue("x is present", map.containsKey(-2L))
    assertTrue("y is present", map.containsKey(-3L))
  }

  /* One coordinate in two is short or long by a byte if the padding is
     skipped, and it fails as a signature mismatch a long way from here. */
  @Test fun `coordinates are always thirty two bytes`() {
    repeat(40) {
      val (map, _) = readMap(WebAuthn.cosePublicKey(key()))
      assertEquals(32, (map[-2L] as ByteArray).size)
      assertEquals(32, (map[-3L] as ByteArray).size)
    }
  }

  @Test fun `authenticator data is rp hash, flags, counter`() {
    val d = WebAuthn.authenticatorData("caturma.localtest.me", WebAuthn.Flags.UP or WebAuthn.Flags.UV, 5)
    assertEquals("no attested data means exactly 37 bytes", 37, d.size)
    assertEquals(hex(WebAuthn.sha256("caturma.localtest.me".toByteArray())), hex(d.copyOfRange(0, 32)))
    assertEquals(0x05, d[32].toInt() and 0xff)
    assertEquals(5, d[36].toInt())
  }

  /* A verifier is entitled to refuse "backed up but not eligible", because
     it cannot happen. A device-bound key must claim neither. */
  @Test fun `a device bound credential claims neither backup bit`() {
    val d = WebAuthn.authenticatorData("rp.example", WebAuthn.Flags.UP or WebAuthn.Flags.UV, 0)
    val flags = d[32].toInt()
    assertEquals(0, flags and WebAuthn.Flags.BE)
    assertEquals(0, flags and WebAuthn.Flags.BS)
  }

  @Test fun `attested credential data carries the aaguid, the id and the key`() {
    val id = ByteArray(32) { it.toByte() }
    val attested = WebAuthn.attestedCredentialData(id, key())
    assertEquals("aaguid is sixteen zeros", hex(ByteArray(16)), hex(attested.copyOfRange(0, 16)))
    assertEquals("length is big endian", 32, (attested[16].toInt() shl 8) or attested[17].toInt())
    assertEquals(hex(id), hex(attested.copyOfRange(18, 50)))
  }

  @Test fun `the attestation object declares none and carries authData`() {
    val authData = WebAuthn.authenticatorData("rp.example", WebAuthn.Flags.UP, 0)
    val obj = WebAuthn.attestationObject(authData)
    /* a3 = 3-pair map, then "fmt" / "none" */
    assertTrue(hex(obj).startsWith("a3" + "63666d74" + "646e6f6e65"))
    assertTrue("authData appears whole", hex(obj).contains(hex(authData)))
  }
}
