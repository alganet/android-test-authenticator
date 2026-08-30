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

    runCatching { assertFor(request) }
      .onSuccess { finishWith(it, null) }
      .onFailure { finishWith(null, it.message ?: "assertion failed") }
  }

  private fun assertFor(request: androidx.credentials.provider.ProviderGetCredentialRequest): String {
    val option = request.credentialOptions.first()
    val requestJson = option.requestData.getString(
      "androidx.credentials.BUNDLE_KEY_REQUEST_JSON",
    ) ?: error("no request json")

    val rpId = org.json.JSONObject(requestJson).getString("rpId")
    val vault = Vault(applicationContext)

    /* The entry the person chose, not merely one that would fit. The
       service puts the id on the intent behind each entry -- see
       TestAuthenticatorService.pending -- because the system does not tell
       an activity which of its own entries was tapped.

       Taking the first match for the rp instead is wrong exactly when it
       matters: two accounts on one site, the second one chosen, the first
       one signed. The server accepts it, because it is a genuine assertion
       from a key it knows -- for the wrong person. No error anywhere. */
    val chosen = intent.getStringExtra(TestAuthenticatorService.EXTRA_CREDENTIAL_ID)
    val credential = when {
      chosen != null -> vault.byId(B64.decode(chosen))
        ?: error("that credential is not on this device any more")
      /* No id means an entry this build did not create -- refuse rather
         than guess, because guessing is the bug this replaced. */
      else -> error("no credential named on the request")
    }

    require(credential.rpId == rpId) {
      "that credential belongs to ${credential.rpId}, not $rpId"
    }

    /* Spent here, before the bytes are built, so the number in authData is
       the one that was persisted. A counter that reaches the verifier
       ahead of the store is a counter that goes backwards after a crash. */
    val count = vault.spend(credential)
    android.util.Log.i(
      "TestAuthenticator",
      "asserting id=${B64.encode(credential.credentialId)} user=${credential.userName} rp=${credential.rpId} count=$count",
    )

    return Ceremony.assertionResponse(
      requestJson = requestJson,
      origin = CallingApp.origin(request.callingAppInfo),
      callerPackage = request.callingAppInfo.packageName,
      credentialId = credential.credentialId,
      userHandle = credential.userHandle,
      signCount = count,
    ) { data -> vault.sign(credential.credentialId, data) }
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
