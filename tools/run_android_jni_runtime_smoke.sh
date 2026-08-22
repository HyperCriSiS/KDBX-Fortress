#!/usr/bin/env bash
set -euo pipefail

package="world.w3b.kdbxfortress.smoke"
apk="android/smoke-app/build/outputs/apk/debug/smoke-app-debug.apk"
component="$package/.SmokeActivity"
ready_file="files/jni-smoke-ready"
result_file="files/jni-smoke-result"

if [[ ! -f "$apk" ]]; then
  echo "Smoke APK not found: $apk" >&2
  exit 1
fi

adb install -r "$apk"
adb shell pm clear "$package" >/dev/null

# Do not use `am start -W`: the intentionally real KDBX KDF work happens in
# onCreate() and may exceed ActivityManager's launch-wait timeout on CI emulators.
adb shell am start -n "$component" >/dev/null

ready=""
for attempt in $(seq 1 90); do
  if ready=$(adb shell run-as "$package" cat "$ready_file" 2>/dev/null | tr -d '\r\n'); then
    if [[ "$ready" == "READY" ]]; then
      break
    fi
  fi
  sleep 1
done

echo "Android JNI lifecycle readiness: ${ready:-<empty>}"

if [[ "$ready" != "READY" ]]; then
  echo "Android JNI runtime smoke never reached the armed lifecycle state." >&2
  adb logcat -d -t 300 "*:S" AndroidRuntime:E KDBXFortress:D || true
  exit 1
fi

# Trigger a real Android foreground -> background lifecycle transition only
# after two real Rust-owned vaults are confirmed live. The Activity writes PASS
# exclusively from onStop() after Rust lock-all invalidates both handles.
adb shell input keyevent KEYCODE_HOME

result=""
for attempt in $(seq 1 60); do
  if result=$(adb shell run-as "$package" cat "$result_file" 2>/dev/null | tr -d '\r\n'); then
    if [[ -n "$result" ]]; then
      break
    fi
  fi
  sleep 1
done

echo "Android JNI runtime result: ${result:-<empty>}"

if [[ "$result" != "PASS" ]]; then
  echo "Android JNI runtime smoke failed; recent app logcat follows." >&2
  adb logcat -d -t 300 "*:S" AndroidRuntime:E KDBXFortress:D || true
  exit 1
fi
