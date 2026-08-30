package dev.caturma.testauthenticator

import android.content.Context
import org.json.JSONObject

/* One ceremony, start to finish, with no Android in it.
 *
 * The service and the activities deal with Credential Manager; this deals
 * with WebAuthn. Keeping them apart is what makes the interesting half
 * testable on a JVM -- a registration response is a pure function of the
 * request, the key and the counter, and none of that needs a device. */
object Ceremony {

  /* clientDataJSON, the way an Android authenticator writes it. `origin` is
     the app's signing certificate, not a url -- there is no web origin on a
     device, which is the fact every relying party has to be taught once. */
  fun clientData(type: String, challenge: String, origin: String): ByteArray =
    JSONObject()
      .put("type", type)
      .put("challenge", challenge)
      .put("origin", origin)
      .put("androidPackageName", "dev.caturma.testauthenticator")
      .toString()
      .toByteArray(Charsets.UTF_8)

  fun register(
    context: Context,
    vault: Vault,
    requestJson: String,
    origin: String,
  ): String {
    val request = JSONObject(requestJson)
    val rp = request.getJSONObject("rp")
    val user = request.getJSONObject("user")
    val rpId = rp.getString("id")
    val challenge = request.getString("challenge")

    val (credential, publicKey) = vault.create(
      rpId = rpId,
      userHandle = Vault.unb64(user.getString("id")),
      userName = user.optString("name", ""),
      requireAuth = !Settings.autoApprove(context),
    )

    val clientDataJson = clientData("webauthn.create", challenge, origin)
    val authData = WebAuthn.authenticatorData(
      rpId = rpId,
      /* AT because this carries the new key; UV because the platform only
         let us get here behind the device's own lock. */
      flags = WebAuthn.Flags.UP or WebAuthn.Flags.UV or WebAuthn.Flags.AT,
      signCount = 0,
      attested = WebAuthn.attestedCredentialData(credential.credentialId, publicKey),
    )

    val id = Vault.b64(credential.credentialId)
    return JSONObject()
      .put("id", id)
      .put("rawId", id)
      .put("type", "public-key")
      .put("authenticatorAttachment", "platform")
      .put(
        "response",
        JSONObject()
          .put("clientDataJSON", Vault.b64(clientDataJson))
          .put("attestationObject", Vault.b64(WebAuthn.attestationObject(authData)))
          .put("transports", org.json.JSONArray(listOf("internal"))),
      )
      .put("clientExtensionResults", JSONObject())
      .toString()
  }

  fun assert(
    vault: Vault,
    credential: Vault.Credential,
    requestJson: String,
    origin: String,
  ): String {
    val request = JSONObject(requestJson)
    val challenge = request.getString("challenge")
    val rpId = request.optString("rpId", credential.rpId)

    val clientDataJson = clientData("webauthn.get", challenge, origin)
    val count = vault.spend(credential)
    val authData = WebAuthn.authenticatorData(
      rpId = rpId,
      flags = WebAuthn.Flags.UP or WebAuthn.Flags.UV,
      signCount = count,
      attested = null,
    )
    val signature = vault.sign(
      credential.credentialId,
      WebAuthn.signedOver(authData, clientDataJson),
    )

    val id = Vault.b64(credential.credentialId)
    return JSONObject()
      .put("id", id)
      .put("rawId", id)
      .put("type", "public-key")
      .put("authenticatorAttachment", "platform")
      .put(
        "response",
        JSONObject()
          .put("clientDataJSON", Vault.b64(clientDataJson))
          .put("authenticatorData", Vault.b64(authData))
          .put("signature", Vault.b64(signature))
          .put("userHandle", Vault.b64(credential.userHandle)),
      )
      .put("clientExtensionResults", JSONObject())
      .toString()
  }
}
