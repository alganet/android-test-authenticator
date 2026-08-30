#!/usr/bin/env bash
# Put this authenticator on the running emulator and make it usable.
#
# Four things, and the point of the script is that three of them are
# invisible until they are missing:
#
#   1. build and install
#   2. enable it as a credential provider -- an installed provider that
#      nothing has enabled is never asked, and the ceremony falls through
#      to whatever else is on the device with a sheet that offers only
#      "use a different phone"
#   3. make it the primary one, so it is what a sheet reaches for first
#   4. turn on auto-approve, without which every ceremony a script starts
#      is refused: Credential Manager rejects synthetic input outright
#      ("Input timestamps are too far apart and unsupported") and there is
#      no gesture a harness can make instead
#
# All of it survives a reboot and none of it survives `pm clear`, which is
# the trap: clearing the app to get a clean slate also un-registers it, and
# the next ceremony fails for a reason that has nothing to do with what was
# being tested. Use `--clear` below instead.
set -euo pipefail

PKG=dev.caturma.testauthenticator
SERVICE="$PKG/.TestAuthenticatorService"
GMS=com.google.android.gms/.auth.api.credentials.credman.service.PasswordAndPasskeyService
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '  %s\n' "$*"; }

if ! adb get-state >/dev/null 2>&1; then
  echo "no device -- start an emulator first" >&2
  exit 1
fi

# An emulator reports sys.boot_completed long before user 0 is unlocked,
# and until it is, an installed app has no resolvable launcher activity.
for _ in $(seq 1 60); do
  case "$(adb shell dumpsys user 2>/dev/null | grep -m1 'Started users state')" in
    *RUNNING_UNLOCKED*) break ;;
  esac
  sleep 2
done

case "${1:-}" in
  --clear)
    adb shell am start -n "$PKG/.MainActivity" --ez clear true >/dev/null 2>&1
    say "forgot every credential (the registration and auto-approve are untouched)"
    exit 0
    ;;
esac

say "building"
"$HERE/gradlew" -p "$HERE" assembleDebug -q

APK="$HERE/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "no apk at $APK" >&2; exit 1; }

say "installing"
adb install -r "$APK" >/dev/null

# Appended rather than replaced: whatever else the device already trusts
# stays trusted, and a second run does not double this one up.
current="$(adb shell settings get secure credential_service 2>/dev/null | tr -d '\r')"
case "$current" in
  *"$SERVICE"*) enabled="$current" ;;
  null|"") enabled="$GMS:$SERVICE" ;;
  *) enabled="$current:$SERVICE" ;;
esac
adb shell settings put secure credential_service "$enabled" >/dev/null
adb shell settings put secure credential_service_primary "$SERVICE" >/dev/null
say "enabled, and primary"

adb shell am start -n "$PKG/.MainActivity" --ez auto true >/dev/null 2>&1
say "auto-approve on -- ceremonies complete without a tap"

# Said back rather than assumed. Every one of these has been wrong at some
# point in this repo's short life, and each failed as something else.
ok=$(adb shell "pm query-services --components -a android.service.credentials.CredentialProviderService" 2>/dev/null | grep -c "$PKG" || true)
[ "$ok" -ge 1 ] || { echo "installed but not declaring the service -- something is wrong" >&2; exit 1; }
say "verified: $(adb shell settings get secure credential_service_primary | tr -d '\r')"
