if [ -z $ANDROID_HOME ]; then
  export ANDROID_HOME=$ANDROID_SDK_ROOT
fi

# Make sure paths are consistent
export ANDROID_USER_HOME="$HOME/.android"
export ANDROID_EMULATOR_HOME="$ANDROID_USER_HOME"
export ANDROID_AVD_HOME="$ANDROID_EMULATOR_HOME/avd"
export PATH="$PATH:$ANDROID_HOME/platform-tools"

emu="$ANDROID_HOME/emulator/emulator"
# cmdline-tools path varies across installations.
# Prefer modern cmdline-tools, then fall back to legacy tools if present.
sdk=""
avd=""
for p in \
  "$ANDROID_HOME/cmdline-tools/latest/bin" \
  "$ANDROID_HOME/cmdline-tools/bin" \
  "$ANDROID_HOME/tools/bin"
do
  if [ -z "$sdk" ] && [ -x "$p/sdkmanager" ]; then
    sdk="$p/sdkmanager"
  fi
  if [ -z "$avd" ] && [ -x "$p/avdmanager" ]; then
    avd="$p/avdmanager"
  fi
done

if [ -z "$sdk" ] || [ -z "$avd" ]; then
  print_error "! Android cmdline-tools not found under ANDROID_HOME=$ANDROID_HOME"
  print_error "  Please install Android SDK Command-line Tools (sdkmanager/avdmanager) and ensure they are under:"
  print_error "    $ANDROID_HOME/cmdline-tools/latest/bin/  (preferred)"
  print_error "  or:"
  print_error "    $ANDROID_HOME/cmdline-tools/bin/"
  print_error "    $ANDROID_HOME/tools/bin/"
  exit 1
fi

boot_timeout=100

if command -v nproc >/dev/null 2>&1; then
  core_count=$(nproc)
elif command -v getconf >/dev/null 2>&1; then
  core_count=$(getconf _NPROCESSORS_ONLN)
elif command -v sysctl >/dev/null 2>&1; then
  core_count=$(sysctl -n hw.ncpu)
else
  core_count=4
fi
if [ $core_count -gt 8 ]; then
  core_count=8
fi

print_title() {
  echo -e "\n\033[44;39m${1}\033[0m\n"
}

print_error() {
  echo -e "\n\033[41;39m${1}\033[0m\n" >&2
}

# $1 = TestClass#method
# $2 = component
am_instrument() {
  set +x
  local out=$(adb shell am instrument -w --user 0 -e class "$1" "$2")
  echo "$out"
  if grep -q 'OK (' <<< "$out"; then
    set -x
    return 0
  else
    set -x
    return 1
  fi
}

# $1 = pkg
wait_for_pm() {
  sleep 5
  adb shell pm uninstall $1 || true
}

run_setup() {
  local variant=$1
  adb shell 'PATH=$PATH:/debug_ramdisk magisk -v'

  # Diagnostics: CI root bring-up is sensitive; print su availability and key props.
  adb shell 'echo "[diag] ro.debuggable=$(getprop ro.debuggable) ro.secure=$(getprop ro.secure)"; \
    echo "[diag] PATH=$PATH"; \
    echo "[diag] su_path=$(command -v su 2>/dev/null || echo none)"; \
    ls -l /system/bin/su /system/xbin/su /sbin/su /debug_ramdisk/su 2>/dev/null || true; \
    ls -l /sbin/magisk /debug_ramdisk/magisk 2>/dev/null || true'
  adb shell 'su -c id 2>&1 || true'

  # Install the Magisk app
  adb install -r -g out/app-${variant}.apk

  # Install the test app
  adb install -r -g out/test.apk

  local app='com.topjohnwu.magisk.test/com.topjohnwu.magisk.test.AppTestRunner'

  # Run setup through the test app
  am_instrument '.Environment#setupEnvironment' $app
}

run_tests() {
  local pkg='com.topjohnwu.magisk.test'
  local self="$pkg/$pkg.TestRunner"
  local app="$pkg/$pkg.AppTestRunner"
  local stub="repackaged.$pkg/$pkg.AppTestRunner"

  # Run app tests
  am_instrument '.MagiskAppTest,.AdditionalTest' $app

  # Test app hiding
  am_instrument '.AppMigrationTest#testAppHide' $self

  # Make sure it still works
  am_instrument '.MagiskAppTest' $stub

  # Test app restore
  am_instrument '.AppMigrationTest#testAppRestore' $self

  # Make sure it still works
  am_instrument '.MagiskAppTest' $app
}
