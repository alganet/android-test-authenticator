package dev.caturma.testauthenticator

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject

/* Where the keys live, and the one thing this app is custodian of.
 *
 * Private keys are generated in the Android Keystore and never leave it --
 * not because a test authenticator needs that guarantee, but because a
 * verifier cannot tell this apart from a real one unless the signatures are
 * produced the same way, and "the same way" is the point of the exercise.
 *
 * Everything else -- which rp, which user, how many times it has signed --
 * is ordinary preferences. None of it is secret and all of it is meant to
 * be read back by a test. */
class Vault(context: Context) {

  private val prefs = context.getSharedPreferences("credentials", Context.MODE_PRIVATE)
  private val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  data class Credential(
    val credentialId: ByteArray,
    val rpId: String,
    val userHandle: ByteArray,
    val userName: String,
    val signCount: Long,
  )

  private fun alias(credentialId: ByteArray) = "cred:" + b64(credentialId)

  /* `requireAuth` is false under auto-approve and true otherwise, and the
     difference is the whole reason auto-approve exists. A Keystore key with
     user authentication required cannot be used without the screen lock
     being answered inside a short window -- which is exactly the gesture a
     harness cannot make. See CreateActivity for why the gesture cannot be
     synthesised either. */
  fun create(
    rpId: String,
    userHandle: ByteArray,
    userName: String,
    requireAuth: Boolean,
  ): Pair<Credential, ECPublicKey> {
    val credentialId = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }

    val spec = KeyGenParameterSpec.Builder(alias(credentialId), KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .apply { if (requireAuth) setUserAuthenticationRequired(true) }
      .build()

    val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    gen.initialize(spec)
    val pair = gen.generateKeyPair()

    val credential = Credential(credentialId, rpId, userHandle, userName, 0)
    save(credential)
    return credential to (pair.public as ECPublicKey)
  }

  /* ES256, which is the only algorithm advertised in the COSE key. The
     signature comes out as the DER sequence WebAuthn expects -- Java's
     SHA256withECDSA already produces that, so nothing here reshapes it. */
  fun sign(credentialId: ByteArray, data: ByteArray): ByteArray {
    val key = keystore.getKey(alias(credentialId), null)
      ?: error("no key for that credential")
    return Signature.getInstance("SHA256withECDSA").run {
      initSign(key as java.security.PrivateKey)
      update(data)
      sign()
    }
  }

  fun forRp(rpId: String): List<Credential> =
    prefs.all.keys.mapNotNull { read(it) }.filter { it.rpId == rpId }

  fun all(): List<Credential> = prefs.all.keys.mapNotNull { read(it) }

  /* Bumped and persisted on every assertion. A counter that never moves is
     one a verifier is entitled to complain about, and one that moves
     backwards is a cloned authenticator -- so this is the state that makes
     the difference visible in a test. */
  fun spend(credential: Credential): Long {
    val next = credential.signCount + 1
    save(credential.copy(signCount = next))
    return next
  }

  private fun save(c: Credential) {
    prefs.edit().putString(
      b64(c.credentialId),
      JSONObject()
        .put("rpId", c.rpId)
        .put("userHandle", b64(c.userHandle))
        .put("userName", c.userName)
        .put("signCount", c.signCount)
        .toString(),
    ).apply()
  }

  private fun read(key: String): Credential? {
    val raw = prefs.getString(key, null) ?: return null
    val j = JSONObject(raw)
    return Credential(
      credentialId = unb64(key),
      rpId = j.getString("rpId"),
      userHandle = unb64(j.getString("userHandle")),
      userName = j.getString("userName"),
      signCount = j.getLong("signCount"),
    )
  }

  fun clear() {
    all().forEach { runCatching { keystore.deleteEntry(alias(it.credentialId)) } }
    prefs.edit().clear().apply()
  }

  companion object {
    /* Kept as names here because the call sites read better, but the
       encoding lives in B64 -- which works under a unit test, and the
       Android one does not. */
    fun b64(b: ByteArray): String = B64.encode(b)
    fun unb64(s: String): ByteArray = B64.decode(s)
  }
}
