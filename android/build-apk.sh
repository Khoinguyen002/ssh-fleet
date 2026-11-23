#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$ROOT_DIR/.." && pwd)"
SDK_DIR="${ANDROID_SDK_ROOT:-$HOME/.local/android-sdk}"
BUILD_TOOLS="$SDK_DIR/build-tools/34.0.0"
PLATFORM_JAR="$SDK_DIR/platforms/android-34/android.jar"

if [ ! -f "$PLATFORM_JAR" ] || [ ! -x "$BUILD_TOOLS/d8" ]; then
  echo "Android SDK 34 / build-tools 34.0.0 not found under $SDK_DIR" >&2
  exit 1
fi

BUILD_DIR="$ROOT_DIR/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/obj" "$BUILD_DIR/dex" "$BUILD_DIR/gen" "$PROJECT_DIR/dist"

echo "==> Linking AndroidManifest..."
"$BUILD_TOOLS/aapt2" link \
  -o "$BUILD_DIR/unaligned.apk" \
  -I "$PLATFORM_JAR" \
  --manifest "$ROOT_DIR/AndroidManifest.xml" \
  --java "$BUILD_DIR/gen" \
  -v

echo "==> Compiling Java sources..."
JAVA_HOME_17="/usr/lib/jvm/java-17-openjdk-amd64"
JAVAC_BIN="javac"
if [ -x "$JAVA_HOME_17/bin/javac" ]; then
  JAVAC_BIN="$JAVA_HOME_17/bin/javac"
fi
"$JAVAC_BIN" --release 11 -classpath "$PLATFORM_JAR" -d "$BUILD_DIR/obj" \
  "$ROOT_DIR/src/com/sshfleet/app/MainActivity.java"

echo "==> Generating classes.dex..."
"$BUILD_TOOLS/d8" --min-api 24 --lib "$PLATFORM_JAR" --output "$BUILD_DIR/dex" \
  "$BUILD_DIR"/obj/com/sshfleet/app/*.class

echo "==> Packaging classes.dex into APK..."
(cd "$BUILD_DIR/dex" && zip -q -u "$BUILD_DIR/unaligned.apk" classes.dex)

echo "==> Aligning APK..."
"$BUILD_TOOLS/zipalign" -f -p 4 "$BUILD_DIR/unaligned.apk" "$BUILD_DIR/aligned.apk"

KEYSTORE="$ROOT_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -v -keystore "$KEYSTORE" \
    -storepass sshfleet123 -keypass sshfleet123 \
    -alias sshfleet -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=ssh-fleet,O=ssh-fleet,C=VN"
fi

OUT_APK="$PROJECT_DIR/dist/ssh-fleet-android.apk"
echo "==> Signing APK -> $OUT_APK"
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:sshfleet123 \
  --key-pass pass:sshfleet123 \
  --ks-key-alias sshfleet \
  --out "$OUT_APK" \
  "$BUILD_DIR/aligned.apk"

"$BUILD_TOOLS/apksigner" verify --verbose "$OUT_APK"
ls -lh "$OUT_APK"
