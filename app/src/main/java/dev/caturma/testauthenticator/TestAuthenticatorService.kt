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

    val entry = CreateEntry.Builder(ENTRY_LABEL, creating())
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

      /* Honour allowCredentials when the rp sends one -- see
         Ceremony.allowedIds, which is where the reasoning and the tests
         for it live. */
      val allowed = Ceremony.allowedIds(option.requestJson)

      vault.forRp(rpId)
        .filter { allowed.isEmpty() || B64.encode(it.credentialId) in allowed }
        .map { credential ->
          PublicKeyCredentialEntry.Builder(
            applicationContext,
            credential.userName.ifEmpty { credential.rpId },
            pending(GetActivity::class.java, credential),
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

  /* MUTABLE because the system fills in the request it is answering.
     Everything else here is about telling two entries apart.

     A PendingIntent is identified by its request code and by the intent's
     action, data, type and component -- and NOT by its extras. So two
     entries built the same way are the same PendingIntent, and
     FLAG_UPDATE_CURRENT quietly rewrites the first one's extras with the
     second's. Both entries then point at the same credential, and picking
     the second in the sheet signs with the first. It looks like the wrong
     account was chosen rather than like a collision.

     Hence both a distinct request code and a distinct data uri: the uri is
     what makes the intents genuinely unequal, the code is belt and braces,
     and the extra is what GetActivity actually reads. */
  /* Registration has one entry, so there is nothing to tell apart. */
  private fun creating(): PendingIntent =
    PendingIntent.getActivity(
      applicationContext,
      0,
      Intent(applicationContext, CreateActivity::class.java),
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

  private fun pending(target: Class<*>, credential: Vault.Credential): PendingIntent {
    val id = B64.encode(credential.credentialId)
    val intent = Intent(applicationContext, target)
      .setData(android.net.Uri.parse("credential:$id"))
      .putExtra(EXTRA_CREDENTIAL_ID, id)
    return PendingIntent.getActivity(
      applicationContext,
      id.hashCode(),
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
  }

  companion object {
    const val ENTRY_LABEL = "Test Authenticator"

    /* Read by GetActivity. The entry the person chose is the only thing
       the system does not tell the activity by itself. */
    const val EXTRA_CREDENTIAL_ID = "dev.caturma.testauthenticator.CREDENTIAL_ID"
  }
}
