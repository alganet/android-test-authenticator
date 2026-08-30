# android-test-authenticator

A passkey credential provider for Android that exists to be **tested against**,
not shipped. It stores keys on the device, needs no Google account and no
network, and it can approve a ceremony without anybody touching the screen.

## Why this exists

An Android emulator cannot complete a passkey ceremony out of the box, and the
reason is not the one everybody assumes.

Android has no built-in passkey store. `CredentialManager` is a router: it
dispatches to apps that implement `CredentialProviderService`, and on a stock
emulator the only one installed is Google Password Manager, which needs a
signed-in Google account to hold anything. So a ceremony gets as far as a sheet
offering *"Use a different phone or tablet"* -- the cross-device QR flow -- and
stops. There is nowhere local to put the key.

That leaves emulator-based development with a choice nobody wants:

| emulator image | `adb root` | provider present | local store |
|---|---|---|---|
| `default` (AOSP) | yes | **none at all** | -- |
| `google_apis` | yes | yes | **no -- needs an account** |
| `google_apis_playstore` | **no** | yes | yes |

Root matters because it is what lets a laptop stand in for a public domain:
rewriting `/system/etc/hosts` so the association check resolves locally, and
mounting a development CA where apps will trust it. Play Store images are
production-signed and refuse `adb root`. So *fake domain* and *local passkey
store* are mutually exclusive across stock images -- unless a provider that
stores locally is simply installed.

That is this.

## What is not true

It is widely repeated -- including in an open issue on Google's own samples --
that a third-party credential provider is never invoked on an emulator without
a Google account, because `beginCreateCredentialRequest` and
`beginGetCredentialRequest` are not called.

That is not what happens on Android 36. With a provider installed and enabled,
`CredentialManager` creates a session for it and starts its process, with no
account on the device at all:

```
CredentialManager: Provider session created and being added for:
  ComponentInfo{<provider>/<service>}
ActivityManager: Start proc <pid>:<provider> for service {...}
```

The routing works. What was missing was something to route *to*.

## What makes it a testing tool

Being a provider is the easy half; several samples do that. The parts that make
this usable from a harness:

 - **no account, no network** -- keys live in the Android Keystore behind the
   device's screen lock, and nothing is synced anywhere
 - **auto-approve** -- a debug-only mode where ceremonies complete without a
   tap. This is not a convenience. Credential Manager rejects synthetic input
   with `Input timestamps are too far apart and unsupported` -- an
   anti-tapjacking guard -- so a ceremony driven by `adb shell input tap`
   fails on principle. A provider that can consent to itself is the only way to
   drive one from a script
 - **inspectable** -- what was stored can be read back over `adb`, so a test
   can assert on it rather than on a screenshot

## Status

Early. The service registers and is invoked; the WebAuthn half is being built
in the open. See `docs/` for what is verified and what is not -- the intent is
that this file never claims more than has actually been run.

## License

Apache-2.0.
