package dev.caturma.testauthenticator

import android.content.Context

/* Auto-approve, and the two gates it is behind.
 *
 * It is compiled out of release builds entirely (BuildConfig), and off by
 * default in debug ones. Turn it on from the settings screen, or over adb:
 *
 *   adb shell am start -n dev.caturma.testauthenticator/.MainActivity \
 *     --ez auto true
 *
 * What it does is skip the consent screen and sign immediately. What it
 * costs is the only thing consent was buying, so nothing here should ever
 * ship enabled -- and a release build cannot. */
object Settings {
  private const val FILE = "settings"
  private const val AUTO = "auto_approve"

  fun autoApprove(context: Context): Boolean =
    BuildConfig.ALLOW_AUTO_APPROVE &&
      context.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(AUTO, false)

  fun setAutoApprove(context: Context, on: Boolean) {
    context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
      .edit().putBoolean(AUTO, on).apply()
  }
}
