#!/bin/sh
# Builds the Android app without Gradle (as build.ps1 does on Windows): cargo for the native
# library, aapt2 for resources and manifest, javac + d8 or R8 for the Java side, then the APK is
# assembled, aligned and signed.
#
#   android/build.sh                 debug APK for arm64-v8a and x86_64
#   android/build.sh --release       R8-optimised, signed with $SAFERDP_KEYSTORE
#
# Needs ANDROID_HOME (platform 36, build-tools 36+), an NDK (ANDROID_NDK_HOME or under
# $ANDROID_HOME/ndk), a JDK 17+, zip, and the Rust targets aarch64-linux-android and
# x86_64-linux-android. Output: android/build/<debug|release>/safe-rdp.apk
set -eu

MIN_SDK=33
TARGET_SDK=36
VERSION_CODE=1
VERSION_NAME=0.1.0

release=false
[ "${1:-}" = "--release" ] && release=true
mode=debug
$release && mode=release

root=$(cd "$(dirname "$0")" && pwd)
out="$root/build/$mode"
sdk=${ANDROID_HOME:?set ANDROID_HOME}
newest() { ls -1 "$1" | sort -V | tail -n 1; }
ndk=${ANDROID_NDK_HOME:-$sdk/ndk/$(newest "$sdk/ndk")}
bt="$sdk/build-tools/$(newest "$sdk/build-tools")"
android_jar="$sdk/platforms/android-$TARGET_SDK/android.jar"
clang="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
for p in "$android_jar" "$clang" "$bt/aapt2" "$bt/zipalign" "$bt/lib/d8.jar"; do
    [ -e "$p" ] || { echo "missing $p" >&2; exit 1; }
done

rm -rf "$out"
stage="$out/apk"
mkdir -p "$stage"

# 1. The native library, always optimised.
for abi in arm64-v8a x86_64; do
    case $abi in
        arm64-v8a) t=aarch64-linux-android ;;
        x86_64) t=x86_64-linux-android ;;
    esac
    var=$(echo "$t" | tr 'a-z-' 'A-Z_')
    export "CARGO_TARGET_${var}_LINKER=$clang"
    # 16 KB pages: Android 15+ devices may use them, and Play requires the alignment.
    export "CARGO_TARGET_${var}_RUSTFLAGS=-C link-arg=--target=$t$MIN_SDK -C link-arg=-Wl,-z,max-page-size=16384"
    cargo build --release --manifest-path "$root/../Cargo.toml" -p safe-rdp-android --target "$t"
    mkdir -p "$stage/lib/$abi"
    cp "$root/../target/$t/release/libsaferdp.so" "$stage/lib/$abi/"
done

# 2. Resources and manifest.
mkdir -p "$out/res" "$out/gen"
"$bt/aapt2" compile --dir "$root/app/res" -o "$out/res/res.zip"
debug_flag=--debug-mode
$release && debug_flag=
"$bt/aapt2" link -I "$android_jar" --manifest "$root/app/AndroidManifest.xml" \
    --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK --version-code $VERSION_CODE --version-name $VERSION_NAME \
    --java "$out/gen" -o "$out/base.apk" "$out/res/res.zip" $debug_flag

# 3. Java, against the platform only (core-lambda-stubs: what javac compiles lambdas against).
mkdir -p "$out/classes" "$out/dex"
find "$root/app/java" "$out/gen" -name '*.java' > "$out/sources.txt"
javac -source 8 -target 8 -bootclasspath "$android_jar:$bt/core-lambda-stubs.jar" -Xlint:-options -encoding UTF-8 \
    -d "$out/classes" @"$out/sources.txt"
find "$out/classes" -name '*.class' > "$out/classes.txt"
if $release; then
    java -cp "$bt/lib/d8.jar" com.android.tools.r8.R8 --release --min-api $MIN_SDK --lib "$android_jar" \
        --pg-conf "$root/app/r8.pro" --output "$out/dex" @"$out/classes.txt"
else
    java -cp "$bt/lib/d8.jar" com.android.tools.r8.D8 --debug --min-api $MIN_SDK --lib "$android_jar" \
        --output "$out/dex" @"$out/classes.txt"
fi
cp "$out/dex/classes.dex" "$stage/"

# 4. Into the APK: the libraries stored uncompressed, so the system maps them straight from it.
(cd "$stage" && zip -q -0 -r "$out/base.apk" lib && zip -q "$out/base.apk" classes.dex)
"$bt/zipalign" -P 16 -f 4 "$out/base.apk" "$out/aligned.apk"

# 5. Signed: debug builds with a key made for this checkout, release builds with yours.
apk="$out/safe-rdp.apk"
if $release; then
    : "${SAFERDP_KEYSTORE:?set SAFERDP_KEYSTORE to your release keystore (apksigner asks for its password)}"
    "$bt/apksigner" sign --ks "$SAFERDP_KEYSTORE" --out "$apk" "$out/aligned.apk"
else
    ks="$root/build/debug.keystore"
    [ -e "$ks" ] || keytool -genkeypair -keystore "$ks" -storepass android -keypass android -alias debug \
        -keyalg EC -groupname secp256r1 -validity 10000 -dname 'CN=safe-rdp debug'
    "$bt/apksigner" sign --ks "$ks" --ks-pass pass:android --ks-key-alias debug --out "$apk" "$out/aligned.apk"
fi
rm -f "$out/base.apk" "$out/aligned.apk"
echo "built $apk"
