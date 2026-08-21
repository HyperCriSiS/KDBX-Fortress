#!/usr/bin/env bash
set -euo pipefail

package="world.w3b.kdbxfortress.smoke"
apk="android/smoke-app/build/outputs/apk/debug/smoke-app-debug.apk"
component="$package/.SmokeActivity"
result_file="files/jni-smoke-result"

if [[ ! -f "$apk" ]]; then
  echo "Smoke APK not found: $apk" >&2
  exit 1
fi

adb install -r "$apk"
adb shell pm clear "$package" >/dev/null
adb shell am start -W -n "$component"

result=""
for attempt in $(seq 1 20); do
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
  adb logcat -d -t 200 "*:S" AndroidRuntime:E KDBXFortress:D || true
  exit 1
fi
