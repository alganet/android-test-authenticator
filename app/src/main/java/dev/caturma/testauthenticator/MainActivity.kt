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

  override fun onResume() {
    super.onResume()
    /* Rebuilt here rather than in onCreate: resuming a screen that counted
       credentials once is a screen that lies about the count for as long
       as it stays in the back stack. */
    if (!isFinishing) render()
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    /* Both reachable from a harness, which is the point of them:
     *
     *   --ez auto true    approve ceremonies without asking
     *   --ez clear true   forget every credential on this device
     *
     * The second one exists because credentials pile up from ceremonies a
     * relying party rejected -- see Vault.create -- and `pm clear` takes
     * auto-approve and the provider's registration with it. A test that
     * wants a clean slate between runs should call this, not that. */
    if (intent.hasExtra("auto")) {
      Settings.setAutoApprove(this, intent.getBooleanExtra("auto", false))
      finish()
      return
    }
    if (intent.getBooleanExtra("clear", false)) {
      val gone = Vault(applicationContext).clear()
      android.util.Log.i("TestAuthenticator", "cleared $gone credential(s)")
      finish()
      return
    }

    render()
  }

  private fun render() {
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
