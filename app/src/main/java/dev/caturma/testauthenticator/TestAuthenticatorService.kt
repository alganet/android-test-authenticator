package dev.caturma.testauthenticator

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.*

/* The seam Credential Manager talks to.
 *
 * Almost nothing happens here, and that is the shape the platform asks for:
 * a provider answers "what could I offer" synchronously and hands back
 * PendingIntents, and the actual work happens when the system launches one.
 * So this file decides what to offer and CreateActivity / GetActivity do
 * the ceremony.
 *
 * Worth recording, because a widely-cited issue on Google's own samples says
 * otherwise: these entry points ARE called on an emulator with no Google
 * account signed in. What is missing on a stock emulator is not the routing,
 * it is a provider to route to. */
class TestAuthenticatorService : CredentialProviderService() {

  override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    if (request !is BeginCreatePublicKeyCredentialRequest) {
      /* Passwords and federated credentials are somebody else's job. */
      callback.onResult(BeginCreateCredentialResponse())
      return
    }

    val entry = CreateEntry.Builder(ENTRY_LABEL, pending(CreateActivity::class.java, request.hashCode()))
      .setDescription(getString(R.string.provider_subtitle))
      .build()

    callback.onResult(BeginCreateCredentialResponse(listOf(entry)))
  }

  override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    val vault = Vault(applicationContext)

    /* One entry per credential this device holds for the rp that asked.
       An empty list is a legitimate answer -- it means "nothing of mine
       matches", and the system will say so on this provider's behalf. */
    val entries = request.beginGetCredentialOptions.flatMap { option ->
      if (option !is BeginGetPublicKeyCredentialOption) return@flatMap emptyList()
      val rpId = runCatching {
        org.json.JSONObject(option.requestJson).getString("rpId")
      }.getOrNull() ?: return@flatMap emptyList()

      vault.forRp(rpId).map { credential ->
        PublicKeyCredentialEntry.Builder(
          applicationContext,
          credential.userName.ifEmpty { credential.rpId },
          pending(GetActivity::class.java, credential.credentialId.contentHashCode()),
          option,
        ).build()
      }
    }

    callback.onResult(BeginGetCredentialResponse(entries))
  }

  override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    Vault(applicationContext).clear()
    callback.onResult(null)
  }

  /* MUTABLE because the system fills in the request it is answering, and
     the request code is distinct per entry so two of them cannot collide
     into one intent. */
  private fun pending(target: Class<*>, code: Int): PendingIntent =
    PendingIntent.getActivity(
      applicationContext,
      code,
      Intent(applicationContext, target),
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

  private companion object {
    const val ENTRY_LABEL = "Test Authenticator"
  }
}
