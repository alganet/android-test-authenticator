package dev.caturma.testauthenticator

import org.json.JSONObject
import java.security.interfaces.ECPublicKey

/* One ceremony, start to finish, with no Android in it.
 *
 * The service and the activities deal with Credential Manager; this deals
 * with WebAuthn. Keeping them apart is what makes the interesting half
 * testable on a JVM -- a registration response is a pure function of the
 * request and the key, and an assertion is one of the request, the counter
 * and whatever the signature turns out to be.
 *
 * The signature is the one thing that cannot be pure, so it arrives as a
 * lambda rather than as a dependency. On a device that is the Android
 * Keystore; in a test it is an ordinary JCE key, and the bytes either
 * produces are checked the same way. Nothing here knows the difference,
 * which is the point: the two bugs that cost the first day of this repo
 * were both in code shaped like this, and both were found in a second once
 * it stopped needing an emulator. */
object Ceremony {

  fun interface Signer {
    fun sign(data: ByteArray): ByteArray
  }

  /* clientDataJSON, the way an Android authenticator writes it. `origin` is
     the caller's signing identity, not a url -- there is no web origin on a
     device, which is the fact every relying party has to be taught once.
     See CallingApp. */
  fun clientData(type: String, challenge: String, origin: String, callerPackage: String): ByteArray =
    JSONObject()
      .put("type", type)
      .put("challenge", challenge)
      .put("origin", origin)
      .put("androidPackageName", callerPackage)
      .toString()
      .toByteArray(Charsets.UTF_8)

  /* Which credentials an rp said it would accept.
   *
   * Empty means no opinion, which is the usual case for discoverable
   * credentials and means "any of mine for this rp". When an rp does name
   * ids, offering anything else is how a provider ends up signing with a
   * key the caller already said it would not take -- a genuine assertion
   * that the server then refuses, with nothing on either side saying why.
   *
   * Tolerant of a malformed list on purpose: a request this cannot read is
   * one where the safe answer is "no opinion", not a crash in a sheet. */
  fun allowedIds(requestJson: String): Set<String> = runCatching {
    val arr = JSONObject(requestJson).optJSONArray("allowCredentials") ?: return emptySet()
    (0 until arr.length()).mapNotNull { arr.optJSONObject(it)?.optString("id")?.ifEmpty { null } }.toSet()
  }.getOrDefault(emptySet())

  /* Registration signs nothing: attestation is `none`, so the attestation
     statement is empty and the only proof on offer is that the key inside
     authData is the one being registered. */
  fun registrationResponse(
    requestJson: String,
    origin: String,
    callerPackage: String,
    credentialId: ByteArray,
    publicKey: ECPublicKey,
  ): String {
    val request = JSONObject(requestJson)
    val rpId = request.getJSONObject("rp").getString("id")
    val challenge = request.getString("challenge")

    val clientDataJson = clientData("webauthn.create", challenge, origin, callerPackage)
    val authData = WebAuthn.authenticatorData(
      rpId = rpId,
      /* AT because this carries the new key; UV because the platform only
         let us get here behind the device's own lock. */
      flags = WebAuthn.Flags.UP or WebAuthn.Flags.UV or WebAuthn.Flags.AT,
      signCount = 0,
      attested = WebAuthn.attestedCredentialData(credentialId, publicKey),
    )

    val id = B64.encode(credentialId)
    return JSONObject()
      .put("id", id)
      .put("rawId", id)
      .put("type", "public-key")
      .put("authenticatorAttachment", "platform")
      .put(
        "response",
        JSONObject()
          .put("clientDataJSON", B64.encode(clientDataJson))
          .put("attestationObject", B64.encode(WebAuthn.attestationObject(authData)))
          .put("transports", org.json.JSONArray(listOf("internal"))),
      )
      .put("clientExtensionResults", JSONObject())
      .toString()
  }

  /* The counter arrives already spent. Whoever owns the storage decides
     what the next value is and persists it; this only puts it in the bytes
     -- so a test can hand in 1 and then 2 and check what a verifier would
     see, without a database. */
  fun assertionResponse(
    requestJson: String,
    origin: String,
    callerPackage: String,
    credentialId: ByteArray,
    userHandle: ByteArray,
    signCount: Long,
    signer: Signer,
  ): String {
    val request = JSONObject(requestJson)
    val challenge = request.getString("challenge")
    val rpId = request.getString("rpId")

    val clientDataJson = clientData("webauthn.get", challenge, origin, callerPackage)
    val authData = WebAuthn.authenticatorData(
      rpId = rpId,
      flags = WebAuthn.Flags.UP or WebAuthn.Flags.UV,
      signCount = signCount,
      attested = null,
    )
    val signature = signer.sign(WebAuthn.signedOver(authData, clientDataJson))

    val id = B64.encode(credentialId)
    return JSONObject()
      .put("id", id)
      .put("rawId", id)
      .put("type", "public-key")
      .put("authenticatorAttachment", "platform")
      .put(
        "response",
        JSONObject()
          .put("clientDataJSON", B64.encode(clientDataJson))
          .put("authenticatorData", B64.encode(authData))
          .put("signature", B64.encode(signature))
          .put("userHandle", B64.encode(userHandle)),
      )
      .put("clientExtensionResults", JSONObject())
      .toString()
  }
}
