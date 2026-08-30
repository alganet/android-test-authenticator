package dev.caturma.testauthenticator

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler

/* Assertion. The mirror of CreateActivity, and the same reasoning about
   auto-approve applies -- see its header. */
class GetActivity : Activity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
    if (request == null) {
      finishWith(null, "no request on the intent")
      return
    }

    if (!Settings.autoApprove(this)) {
      finishWith(null, "consent ui not implemented -- enable auto-approve")
      return
    }

    runCatching {
      val option = request.credentialOptions.first()
      val requestJson = option.requestData.getString(
        "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
      ) ?: error("no request json")

      val rpId = org.json.JSONObject(requestJson).getString("rpId")
      val vault = Vault(applicationContext)
      val credential = vault.forRp(rpId).firstOrNull()
        ?: error("no credential for $rpId")

      val origin = CallingApp.origin(request.callingAppInfo)

      Ceremony.assert(vault, credential, requestJson, origin)
    }
      .onSuccess { finishWith(it, null) }
      .onFailure { finishWith(null, it.message ?: "assertion failed") }
  }

  private fun finishWith(responseJson: String?, error: String?) {
    val result = Intent()
    if (responseJson != null) {
      PendingIntentHandler.setGetCredentialResponse(
        result,
        GetCredentialResponse(PublicKeyCredential(responseJson)),
      )
    } else {
      PendingIntentHandler.setGetCredentialException(
        result,
        GetCredentialUnknownException(error),
      )
    }
    setResult(RESULT_OK, result)
    finish()
  }
}
