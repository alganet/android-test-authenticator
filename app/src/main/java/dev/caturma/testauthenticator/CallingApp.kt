package dev.caturma.testauthenticator

import androidx.credentials.provider.CallingAppInfo
import java.security.MessageDigest

/* Who is asking, in the form a relying party can check.
 *
 * There is no web origin on a device, so WebAuthn on Android substitutes
 * the caller's signing identity:
 *
 *   android:apk-key-hash:<base64url of SHA-256 over the signing certificate>
 *
 * That is the same number `keytool -list -v` prints as SHA256, which is why
 * a server can be told it out of band -- caturma reads it off the debug
 * keystore at boot. Get it wrong and the ceremony completes, the signature
 * verifies, and the server still refuses with `bad_origin`, because the
 * credential was made for an app it does not answer for. The package name
 * is not this. It looks close enough to pass review and is not the same
 * value at all. */
object CallingApp {

  fun origin(info: CallingAppInfo): String {
    /* Browsers and other privileged callers get a real web origin, and the
       platform hands it over only to those. Everything else falls through
       to the signature, which is the ordinary case here. */
    runCatching { info.origin }.getOrNull()?.let {
      android.util.Log.i("TestAuthenticator", "privileged origin: $it")
      return it
    }

    val signature = info.signingInfo.apkContentsSigners.firstOrNull()
      ?: error("the caller has no signing certificate")

    val digest = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
    val origin = "android:apk-key-hash:" + Vault.b64(digest)
    android.util.Log.i("TestAuthenticator", "origin for ${info.packageName}: $origin")
    return origin
  }
}
