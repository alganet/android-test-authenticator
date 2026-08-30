package dev.caturma.testauthenticator

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/* A round trip, checked the way a relying party checks it.
 *
 * Registration produces a key; assertion signs with it; and the test
 * verifies that signature over the same bytes a server reconstructs --
 * authenticatorData followed by SHA-256 of clientDataJSON. If the flags,
 * the counter, the rp hash or the encoding of any of it drifts, the
 * signature stops verifying here rather than in a log line on a device.
 *
 * This is the test that would have caught both of the first day's bugs. */
class CeremonyTest {

  private val rpId = "caturma.localtest.me"
  private val origin = "android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w"
  private val pkg = "app.caturma"

  private fun keys(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply {
      initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

  private fun registrationRequest(challenge: String) = JSONObject()
    .put("challenge", challenge)
    .put("rp", JSONObject().put("id", rpId).put("name", "caturma"))
    .put("user", JSONObject().put("id", B64.encode("u1".toByteArray())).put("name", "nina"))
    .toString()

  private fun assertionRequest(challenge: String) = JSONObject()
    .put("challenge", challenge)
    .put("rpId", rpId)
    .toString()

  private fun response(json: String) = JSONObject(json).getJSONObject("response")

  @Test fun `registration carries the challenge, the origin and the key`() {
    val pair = keys()
    val id = ByteArray(32) { 7 }
    val out = Ceremony.registrationResponse(
      registrationRequest("chal-1"), origin, pkg, id, pair.public as ECPublicKey,
    )

    val client = JSONObject(String(B64.decode(response(out).getString("clientDataJSON"))))
    assertEquals("webauthn.create", client.getString("type"))
    assertEquals("chal-1", client.getString("challenge"))
    assertEquals(origin, client.getString("origin"))
    assertEquals(pkg, client.getString("androidPackageName"))

    assertEquals(B64.encode(id), JSONObject(out).getString("id"))
    assertEquals("platform", JSONObject(out).getString("authenticatorAttachment"))
  }

  /* The whole point of the exercise: bytes this produced, verified by an
     ordinary JCE verifier against the key this registered. */
  @Test fun `an assertion verifies against the registered key`() {
    val pair = keys()
    val id = ByteArray(32) { 3 }
    val userHandle = "u1".toByteArray()

    val out = Ceremony.assertionResponse(
      assertionRequest("chal-2"), origin, pkg, id, userHandle, signCount = 1,
    ) { data ->
      Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(data); sign() }
    }

    val r = response(out)
    val authData = B64.decode(r.getString("authenticatorData"))
    val clientDataJson = B64.decode(r.getString("clientDataJSON"))
    val signature = B64.decode(r.getString("signature"))

    /* Exactly what a server reconstructs before calling verify. */
    val signed = authData + MessageDigest.getInstance("SHA-256").digest(clientDataJson)
    val ok = Signature.getInstance("SHA256withECDSA").run {
      initVerify(pair.public); update(signed); verify(signature)
    }
    assertTrue("the signature does not verify over authData || sha256(clientData)", ok)

    assertArrayEquals(userHandle, B64.decode(r.getString("userHandle")))
    assertEquals(rpId, JSONObject(assertionRequest("chal-2")).getString("rpId"))
  }

  @Test fun `an assertion is bound to the rp and the challenge it was asked for`() {
    val pair = keys()
    val out = Ceremony.assertionResponse(
      assertionRequest("chal-3"), origin, pkg, ByteArray(32), "u".toByteArray(), 4,
    ) { data -> Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(data); sign() } }

    val r = response(out)
    val client = JSONObject(String(B64.decode(r.getString("clientDataJSON"))))
    assertEquals("webauthn.get", client.getString("type"))
    assertEquals("chal-3", client.getString("challenge"))

    val authData = B64.decode(r.getString("authenticatorData"))
    val expected = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
    assertArrayEquals("rpIdHash is not this rp", expected, authData.copyOfRange(0, 32))
  }

  /* A counter that never moves is one a verifier may complain about, and
     one that goes backwards is a cloned authenticator. Whoever owns the
     storage decides the number; this pins that the number reaches the
     bytes, big-endian, where a verifier reads it. */
  @Test fun `the sign counter reaches the bytes and moves forward`() {
    val pair = keys()
    fun at(count: Long): Long {
      val out = Ceremony.assertionResponse(
        assertionRequest("c"), origin, pkg, ByteArray(32), "u".toByteArray(), count,
      ) { d -> Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(d); sign() } }
      val a = B64.decode(response(out).getString("authenticatorData"))
      return ((a[33].toLong() and 0xff) shl 24) or ((a[34].toLong() and 0xff) shl 16) or
        ((a[35].toLong() and 0xff) shl 8) or (a[36].toLong() and 0xff)
    }
    assertEquals(1L, at(1))
    assertEquals(2L, at(2))
    assertEquals(258L, at(258))
  }

  /* An assertion must not carry attested credential data: AT is a
     registration flag, and 37 bytes is the whole of what a verifier
     expects to parse. */
  @Test fun `an assertion carries no attested credential data`() {
    val pair = keys()
    val out = Ceremony.assertionResponse(
      assertionRequest("c"), origin, pkg, ByteArray(32), "u".toByteArray(), 1,
    ) { d -> Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(d); sign() } }
    val a = B64.decode(response(out).getString("authenticatorData"))
    assertEquals(37, a.size)
    assertEquals(0, a[32].toInt() and WebAuthn.Flags.AT)
  }
}

/* Which credentials an rp is willing to accept, and what silence means. */
class AllowCredentialsTest {

  @Test fun `no list at all is no opinion`() {
    assertTrue(Ceremony.allowedIds("""{"challenge":"c","rpId":"r"}""").isEmpty())
  }

  @Test fun `an empty list is no opinion`() {
    assertTrue(Ceremony.allowedIds("""{"allowCredentials":[]}""").isEmpty())
  }

  @Test fun `named ids are the whole of what may be offered`() {
    val ids = Ceremony.allowedIds(
      """{"allowCredentials":[{"type":"public-key","id":"AAA"},{"type":"public-key","id":"BBB"}]}""",
    )
    assertEquals(setOf("AAA", "BBB"), ids)
  }

  /* A request this cannot read is one where the safe answer is "no
     opinion". Crashing here would take out the sheet. */
  @Test fun `nonsense is no opinion rather than an exception`() {
    assertTrue(Ceremony.allowedIds("not json at all").isEmpty())
    assertTrue(Ceremony.allowedIds("""{"allowCredentials":"nope"}""").isEmpty())
    assertTrue(Ceremony.allowedIds("""{"allowCredentials":[{"type":"public-key"}]}""").isEmpty())
  }
}
