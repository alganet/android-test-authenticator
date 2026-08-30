# What is verified, and what is not

This file is the honest ledger. Nothing moves from the second list to the
first without having actually been run.

## Verified

 - **Credential Manager invokes a third-party provider on an emulator with
   no Google account.** Observed on an `android-36 google_apis` AVD, arm64,
   zero accounts on the device, using Google's own `MyVault` sample as the
   provider:

   ```
   CredentialManager: Provider session created and being added for:
     ComponentInfo{com.example.android.authentication.myvault/...}
   ActivityManager: Start proc 9366:com.example.android.authentication.myvault
     for service {...}
   ```

   This contradicts the prevailing reading of
   https://github.com/android/identity-samples/issues/123 , which concludes a
   Google account is required "with or without a third party credential
   provider". On Android 36 the routing happens. What a stock emulator lacks
   is a provider with somewhere local to put the key.

 - **Google Password Manager cannot be that provider without an account.**
   With attachment unset it offers only "Use a different phone or tablet";
   with `authenticatorAttachment: "platform"` forced it fails immediately and
   draws no sheet at all. Relaxing `residentKey` to `discouraged` changes
   nothing, so discoverability is not the gate.

 - **Credential Manager refuses synthetic input.** A ceremony driven with
   `adb shell input tap` is rejected with `Input timestamps are too far apart
   and unsupported`. This is why auto-approve exists.

 - **This provider is invoked, offers itself as a local destination, and
   returns a response Credential Manager accepts.** On the same emulator,
   with auto-approve on:

   ```
   CredentialManager: Provider session created and being added for:
     ComponentInfo{dev.caturma.testauthenticator/...TestAuthenticatorService}
   CredentialManager: Remote provider responded with a valid response
   ActivityTaskManager: START u0 {cmp=dev.caturma.testauthenticator/.CreateActivity}
   CredentialManager: Final credential received from:
     dev.caturma.testauthenticator/...TestAuthenticatorService
   ```

   The system sheet offered "Test Authenticator -- Passkeys, on this device,
   for tests" as a destination, beside Google's. That is the sheet a stock
   emulator cannot draw, and the reason this repo exists.

 - **Auto-approve gets past the anti-tapjacking guard.** The ceremony
   completed without the consent screen being tapped.

## Not verified yet

 - **The response shape is wrong.** Credential Manager accepts it, but the
   relying party app could not read it: the ceremony ends with the app
   saying the device answered something unparseable, and no request reaches
   the server. So the CBOR, the attestation object, or the JSON field names
   in Ceremony.register are not yet what a client library expects. This is
   the next thing to fix and the first thing to write a test for.

 - A complete registration accepted by a real relying party.
 - A complete assertion, and whether the sign counter is read the way a
   verifier expects across two ceremonies.
 - Whether `callingAppInfo.origin` is populated on this platform version, or
   whether the apk-key-hash fallback in the activities is the path actually
   taken.
 - Anything at all on a physical device.

## Known gaps

 - There is no consent UI. Without auto-approve the ceremony is refused with
   a message saying so, rather than showing an empty screen.
 - Assertion picks the first credential for the rp rather than the one the
   entry was built for.
