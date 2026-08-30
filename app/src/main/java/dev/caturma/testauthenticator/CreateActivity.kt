package dev.caturma.testauthenticator

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest

/* Registration, once the system has launched us.
 *
 * In auto-approve this finishes without drawing anything, and that is the
 * feature rather than a shortcut. Credential Manager rejects synthetic input
 * outright -- `Input timestamps are too far apart and unsupported`, its
 * anti-tapjacking guard -- so a ceremony driven by `adb shell input tap`
 * cannot be consented to from a script no matter how the taps are timed. A
 * provider that consents to itself is the only door left, which is why this
 * app exists and why that door is nailed shut in release builds. */
class CreateActivity : Activity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
    if (request == null) {
      finishWith(null, "no request on the intent")
      return
    }

    if (!Settings.autoApprove(this)) {
      /* The honest path: ask. Not built yet -- see docs/STATUS.md, which
         says so rather than letting an empty screen imply otherwise. */
      finishWith(null, "consent ui not implemented -- enable auto-approve")
      return
    }

    runCatching { register(request) }
      .onSuccess { finishWith(it, null) }
      .onFailure { finishWith(null, it.message ?: "registration failed") }
  }

  /* The Android half: read the request, make a key, and hand both to the
     ceremony -- which knows WebAuthn and nothing about any of this. */
  private fun register(request: ProviderCreateCredentialRequest): String {
    val requestJson = request.callingRequest.credentialData.getString(
      "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
    ) ?: error("no request json")

    val json = org.json.JSONObject(requestJson)
    val user = json.getJSONObject("user")
    val vault = Vault(applicationContext)

    val (credential, publicKey) = vault.create(
      rpId = json.getJSONObject("rp").getString("id"),
      userHandle = B64.decode(user.getString("id")),
      userName = user.optString("name", ""),
      /* A key that demands the screen lock cannot be used by a harness --
         the gesture that answers it is the one Credential Manager refuses
         to accept synthetically. So under auto-approve it does not. */
      requireAuth = !Settings.autoApprove(this),
      testMode = Settings.autoApprove(this),
    )

    return Ceremony.registrationResponse(
      requestJson = requestJson,
      origin = CallingApp.origin(request.callingAppInfo),
      callerPackage = request.callingAppInfo.packageName,
      credentialId = credential.credentialId,
      publicKey = publicKey,
    )
  }

  private fun finishWith(responseJson: String?, error: String?) {
    val result = Intent()
    if (responseJson != null) {
      PendingIntentHandler.setCreateCredentialResponse(
        result,
        CreatePublicKeyCredentialResponse(responseJson),
      )
      setResult(RESULT_OK, result)
    } else {
      PendingIntentHandler.setCreateCredentialException(
        result,
        CreateCredentialUnknownException(error),
      )
      setResult(RESULT_OK, result)
    }
    finish()
  }
}
