#!/usr/bin/env bash
set -euo pipefail

production_package="world.w3b.kdbxfortress"
production_apk="android/app/build/outputs/apk/debug/app-debug.apk"
production_component="$production_package/.MainActivity"

package="world.w3b.kdbxfortress.smoke"
apk="android/smoke-app/build/outputs/apk/debug/smoke-app-debug.apk"
component="$package/.SmokeActivity"
ready_file="files/jni-smoke-ready"
result_file="files/jni-smoke-result"

if [[ ! -f "$production_apk" ]]; then
  echo "Production APK not found: $production_apk" >&2
  exit 1
fi

if [[ ! -f "$apk" ]]; then
  echo "Smoke APK not found: $apk" >&2
  exit 1
fi

# Prove that the real production Activity starts successfully with the Compose
# shell and shared native-bridge module before running the deeper fixture probe.
adb install -r "$production_apk"
adb shell pm clear "$production_package" >/dev/null
adb logcat -c
adb shell am start -W -n "$production_component"
sleep 1

if ! adb shell pidof "$production_package" >/dev/null; then
  echo "Production Compose shell did not remain alive after launch." >&2
  adb logcat -d -t 300 "*:S" AndroidRuntime:E KDBXFortress:D || true
  exit 1
fi

if ! adb shell dumpsys activity activities | grep -Fq "$production_package/.MainActivity"; then
  echo "Production MainActivity is not present in the active task after launch." >&2
  adb logcat -d -t 300 "*:S" AndroidRuntime:E KDBXFortress:D || true
  exit 1
fi

echo "Android production Compose shell: PASS"
adb shell input keyevent KEYCODE_HOME
adb shell am force-stop "$production_package"

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
