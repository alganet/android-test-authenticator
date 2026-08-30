package dev.caturma.testauthenticator

/* base64url, no padding -- the encoding every WebAuthn JSON field uses, so
   nothing downstream has to translate.
 *
 * java.util.Base64 rather than android.util.Base64, and that is not a
 * preference. The Android one exists only on a device: under a JVM unit
 * test it is a stub that answers null, so every field encoded with it comes
 * out empty and the tests pass against nothing. This one is in the JDK and
 * on Android since API 26, and behaves identically in both. */
object B64 {
  private val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
  private val decoder = java.util.Base64.getUrlDecoder()

  fun encode(b: ByteArray): String = encoder.encodeToString(b)
  fun decode(s: String): ByteArray = decoder.decode(s)
}
