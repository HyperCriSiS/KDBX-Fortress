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

# Exercise the real production Open action rather than only proving Activity
# launch. Compose semantics are exposed through UIAutomator; tapping the button
# must hand control to Android's DocumentsUI SAF picker.
ui_dump_device="/sdcard/kdbx-fortress-ui.xml"
ui_dump_host="${RUNNER_TEMP:-/tmp}/kdbx-fortress-ui.xml"
adb shell uiautomator dump "$ui_dump_device" >/dev/null
adb exec-out cat "$ui_dump_device" > "$ui_dump_host"

read -r open_x open_y < <(
  python3 - "$ui_dump_host" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
for node in root.iter("node"):
    if node.attrib.get("text") != "Open vault":
        continue
    bounds = node.attrib.get("bounds", "")
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    if match is None:
        continue
    left, top, right, bottom = map(int, match.groups())
    print((left + right) // 2, (top + bottom) // 2)
    raise SystemExit(0)

raise SystemExit("Open vault UI node not found")
PY
)

adb shell input tap "$open_x" "$open_y"

documents_ui=""
for attempt in $(seq 1 10); do
  documents_ui=$(adb shell dumpsys activity activities | grep -im1 "documentsui" || true)
  if [[ -n "$documents_ui" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "$documents_ui" ]]; then
  echo "Open vault did not delegate to Android DocumentsUI/SAF." >&2
  adb shell uiautomator dump /dev/tty 2>/dev/null || true
  adb shell dumpsys activity activities | head -n 160 || true
  exit 1
fi

echo "Android SAF open picker: PASS"
adb shell input keyevent KEYCODE_BACK
sleep 1

if ! adb shell dumpsys activity activities | grep -Fq "$production_package/.MainActivity"; then
  echo "Production MainActivity did not resume after dismissing the SAF picker." >&2
  exit 1
fi

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
