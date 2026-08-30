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

 - **A complete registration, accepted by a real relying party.** An account
   was created end to end against a WebAuthn server that verifies
   attestation itself: challenge, origin, rpIdHash, user presence, the COSE
   key re-encoded and the signature checked. No Google account on the
   device, nothing over the network, no cloud of any kind.

   Two bugs were between here and there, and both are worth naming because
   neither announced itself:

   1. The COSE key labels were encoded as the CBOR *argument* rather than
      the negative number -- `nint(6)` where `nint(-7)` was meant. The key
      still parsed far enough to fail as `bad_attestation`, which names a
      file and not a label. CborTest pins it now.
   2. The origin was built from the caller's package name. WebAuthn on
      Android substitutes the caller's signing identity for a web origin --
      base64url of SHA-256 over the signing certificate -- and the package
      name looks close enough to pass review while being a different value.
      That failed as `bad_origin`, which reads as "wrong app" rather than
      "wrong hash". See CallingApp.kt.
 - **A complete assertion on a device, and the right one.** Two accounts
   registered against one rp through this provider, both offered in the
   system sheet, and the second one chosen: the provider asserted that
   credential's id, the app signed in as that person, and on the server
   only that credential's counter moved (0 to 1) with the other left
   untouched. Under the previous code the first credential stored for the
   rp was signed with regardless of which was tapped, which is a genuine
   assertion for the wrong person and reports no error anywhere.

 - ~~A complete assertion on a device.~~ The bytes are pinned on a JVM --
   an assertion produced here verifies under an ordinary JCE verifier over
   authData || SHA-256(clientDataJSON), which is what a server
   reconstructs -- and the counter, the rp hash and the absence of attested
   data are asserted with it. What has not happened is one of these going
   through Credential Manager and being accepted by a relying party.
 - Whether `callingAppInfo.origin` is populated on this platform version, or
   whether the apk-key-hash fallback in the activities is the path actually
   taken.
 - Anything at all on a physical device.

## Known gaps

 - **Credentials accumulate from registrations the relying party rejected.**
   A provider stores the key when it makes it, and Credential Manager never
   tells it whether the rp accepted -- so a ceremony that fails downstream
   leaves a credential the server has never heard of. Those are then
   offered in the sheet, and choosing one fails as `bad_credential`, which
   reads as a broken passkey rather than as one that was never really made.
   Eight had piled up during one afternoon of debugging.

   Re-registering the same user for the same rp now replaces rather than
   adds, which is what WebAuthn asks of a platform authenticator -- but it
   does not fix this, because a relying party that mints a fresh user id
   per attempt produces genuinely distinct credentials. Clearing the app's
   data is the only cure today. A test harness should probably do that
   between runs, and this should probably grow an adb-reachable way to.

 - The settings screen builds its list in onCreate, so resuming it shows a
   stale count.

 - There is no consent UI. Without auto-approve the ceremony is refused with
   a message saying so, rather than showing an empty screen.
 - Nothing has been run on a physical device.
