#!/usr/bin/env bash
# Garudatva v3 — Real Android sandbox provisioning
#
# Sets up everything Stage 2 (Dynamic Analysis) needs for a REAL emulator
# run: Android SDK cmdline-tools, platform-tools, the emulator package, a
# system image, an AVD named to match config.py's AVD_NAME, and a
# frida-server binary matching the installed `frida` Python package's
# version. Nothing here is simulated — if any step fails, fix that step
# and re-run; this script does not paper over a missing piece.
#
# Usage:
#   ANDROID_SDK_ROOT=$HOME/android-sdk ./setup_android_sandbox.sh
#
# After this completes, verify with:
#   python3 -c "from core.dynamic.sandbox_manager import check_sandbox_prerequisites as c; print(c() or 'READY')"

set -euo pipefail

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
AVD_NAME="${AVD_NAME:-garudatva_sandbox}"
API_LEVEL="${API_LEVEL:-33}"
CMDLINE_TOOLS_VERSION="11076708" # cmdline-tools r11076708 (Android SDK Command-Line Tools)

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "== Garudatva Android sandbox setup =="
echo "ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT"
echo "AVD_NAME=$AVD_NAME"
echo "Host: $OS $ARCH"
echo

# ── 1. Hardware acceleration check (fail fast — nothing else matters without this) ──
if [ "$OS" = "Linux" ]; then
  if [ ! -e /dev/kvm ]; then
    echo "FATAL: /dev/kvm not found."
    echo "The Android emulator needs KVM to run at usable speed (or at all, in a container)."
    echo "  - Bare metal/VM with nested virt: enable nested virtualization for this VM,"
    echo "    then check 'egrep -c \"(vmx|svm)\" /proc/cpuinfo' is > 0 and /dev/kvm exists."
    echo "  - Docker: run with --device /dev/kvm and add the container user to the kvm group."
    echo "This script cannot proceed without host-level hypervisor access — that is a"
    echo "platform/infrastructure decision, not something this script can install."
    exit 1
  fi
  echo "[ok] /dev/kvm present"
elif [ "$OS" = "Darwin" ]; then
  if ! sysctl -n kern.hv_support 2>/dev/null | grep -q 1; then
    echo "FATAL: macOS Hypervisor.framework not available (kern.hv_support != 1)."
    echo "Real hardware (not a nested macOS VM) is required for HVF acceleration."
    exit 1
  fi
  echo "[ok] Hypervisor.framework available (HVF)"
else
  echo "WARNING: untested OS '$OS' — continuing, but acceleration may not work."
fi

# ── 2. Java (cmdline-tools requires a JDK) ──────────────────────────────
if ! command -v java >/dev/null 2>&1; then
  echo "FATAL: 'java' not found. Install a JDK 17+ (e.g. 'apt install openjdk-17-jre-headless')."
  exit 1
fi
echo "[ok] java: $(java -version 2>&1 | head -1)"

# ── 3. Android cmdline-tools ─────────────────────────────────────────────
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
if [ ! -x "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]; then
  echo "Installing Android cmdline-tools..."
  case "$OS" in
    Linux)  CT_URL="https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" ;;
    Darwin) CT_URL="https://dl.google.com/android/repository/commandlinetools-mac-${CMDLINE_TOOLS_VERSION}_latest.zip" ;;
    *) echo "FATAL: no known cmdline-tools package for $OS"; exit 1 ;;
  esac
  tmp_zip="$(mktemp)"
  curl -fsSL "$CT_URL" -o "$tmp_zip"
  rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  unzip -q "$tmp_zip" -d "$ANDROID_SDK_ROOT/cmdline-tools"
  mv "$ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  rm -f "$tmp_zip"
fi
SDKMANAGER="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/avdmanager"
echo "[ok] cmdline-tools at $ANDROID_SDK_ROOT/cmdline-tools/latest"

# ── 4. platform-tools, emulator, system image ────────────────────────────
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
  IMAGE_ABI="arm64-v8a"
else
  IMAGE_ABI="x86_64"
fi
SYSTEM_IMAGE="system-images;android-${API_LEVEL};google_apis;${IMAGE_ABI}"

yes | "$SDKMANAGER" --sdk_root="$ANDROID_SDK_ROOT" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" --sdk_root="$ANDROID_SDK_ROOT" \
  "platform-tools" "emulator" "$SYSTEM_IMAGE"
echo "[ok] platform-tools, emulator, $SYSTEM_IMAGE installed"

# ── 5. Create the AVD (matches config.py's settings.AVD_NAME) ────────────
if ! "$ANDROID_SDK_ROOT/emulator/emulator" -list-avds | grep -qx "$AVD_NAME"; then
  echo "no" | "$AVDMANAGER" create avd \
    --name "$AVD_NAME" \
    --package "$SYSTEM_IMAGE" \
    --device "pixel_6" \
    --force
  echo "[ok] AVD '$AVD_NAME' created"
else
  echo "[ok] AVD '$AVD_NAME' already exists"
fi

# ── 6. frida-server matching the installed frida Python package version ──
FRIDA_VERSION="$(python3 -c 'import frida; print(frida.__version__)' 2>/dev/null || true)"
if [ -z "$FRIDA_VERSION" ]; then
  echo "WARNING: 'frida' Python package not importable — skipping frida-server download."
  echo "Install it first ('pip install -r requirements.txt'), then re-run this script."
else
  FRIDA_ARCH="android-${IMAGE_ABI/arm64-v8a/arm64}"
  DEST="/opt/frida/frida-server-${FRIDA_VERSION}-${FRIDA_ARCH}"
  if [ ! -x "$DEST" ]; then
    echo "Downloading frida-server $FRIDA_VERSION for $FRIDA_ARCH..."
    sudo mkdir -p /opt/frida
    tmp_xz="$(mktemp).xz"
    curl -fsSL \
      "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-${FRIDA_ARCH}.xz" \
      -o "$tmp_xz"
    xz -d -c "$tmp_xz" | sudo tee "$DEST" >/dev/null
    sudo chmod 755 "$DEST"
    rm -f "$tmp_xz"
  fi
  echo "[ok] frida-server at $DEST (must match the AVD's ABI — this script assumes $FRIDA_ARCH)"
fi

echo
echo "== Done. Export these before starting the backend: =="
echo "  export ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT"
echo "  export PATH=\"\$ANDROID_SDK_ROOT/emulator:\$ANDROID_SDK_ROOT/platform-tools:\$PATH\""
echo
echo "Then verify: python3 -c \"from core.dynamic.sandbox_manager import check_sandbox_prerequisites as c; print(c() or 'READY')\""
