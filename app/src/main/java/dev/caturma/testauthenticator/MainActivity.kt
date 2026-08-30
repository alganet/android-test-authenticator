package dev.caturma.testauthenticator

import android.app.Activity
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/* The settings screen a credential provider is required to name, and the
   one place auto-approve can be turned on by hand.
 *
 * A harness does not need it -- `--ez auto true` on the launch intent sets
 * the same flag and exits -- so this stays deliberately plain. */
class MainActivity : Activity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    /* adb shell am start -n dev.caturma.testauthenticator/.MainActivity --ez auto true */
    if (intent.hasExtra("auto")) {
      Settings.setAutoApprove(this, intent.getBooleanExtra("auto", false))
      finish()
      return
    }

    val pad = (16 * resources.displayMetrics.density).toInt()
    val column = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(pad, pad, pad, pad)
    }

    column.addView(
      TextView(this).apply {
        text = getString(R.string.app_name)
        textSize = 22f
      },
    )

    val vault = Vault(applicationContext)
    column.addView(
      TextView(this).apply {
        text = if (BuildConfig.ALLOW_AUTO_APPROVE) {
          "${vault.all().size} credential(s) on this device"
        } else {
          "${vault.all().size} credential(s) -- auto-approve is not in this build"
        }
        setPadding(0, pad, 0, pad)
      },
    )

    if (BuildConfig.ALLOW_AUTO_APPROVE) {
      column.addView(
        Switch(this).apply {
          text = "Approve ceremonies without asking"
          isChecked = Settings.autoApprove(context)
          setOnCheckedChangeListener { _, on -> Settings.setAutoApprove(context, on) }
        },
      )
    }

    for (c in vault.all()) {
      column.addView(
        TextView(this).apply {
          text = "${c.rpId} · ${c.userName} · signed ${c.signCount}×"
          setPadding(0, pad / 2, 0, 0)
        },
      )
    }

    setContentView(ScrollView(this).apply { addView(column) })
  }
}
