# Builds the Android app without Gradle: cargo (the native library), aapt2 (resources and
# manifest), javac + d8 or R8 (the Java side), then the APK is assembled, aligned and signed.
#
#   android\build.ps1                       debug APK for arm64-v8a and x86_64 (emulator)
#   android\build.ps1 -Release              R8-optimised, signed with $env:SAFERDP_KEYSTORE
#   android\build.ps1 -Abi x86_64           one ABI only
#
# Needs the Android SDK (platform 36, build-tools 36+), the NDK, a JDK 17+ and the Rust targets
# aarch64-linux-android / x86_64-linux-android. Output: android\build\<debug|release>\safe-rdp.apk

param(
    [switch]$Release,
    [ValidateSet('arm64-v8a', 'x86_64')][string[]]$Abi = @('arm64-v8a', 'x86_64')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$MinSdk = 33
$TargetSdk = 36
$VersionCode = 1
$VersionName = '0.1.0'

$root = $PSScriptRoot
$mode = if ($Release) { 'release' } else { 'debug' }
$out = Join-Path $root "build\$mode"
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
function Newest($dir) { (Get-ChildItem $dir -Directory | Sort-Object { [version]($_.Name -replace '-.*', '') } | Select-Object -Last 1).FullName }
$ndk = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { Newest (Join-Path $sdk 'ndk') }
$bt = Newest (Join-Path $sdk 'build-tools')
$androidJar = Join-Path $sdk "platforms\android-$TargetSdk\android.jar"
$clang = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'
$java = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin' } else { Split-Path (Get-Command javac).Source }
foreach ($p in $androidJar, $clang, "$bt\aapt2.exe", "$bt\zipalign.exe", "$bt\lib\d8.jar", "$java\javac.exe") {
    if (-not (Test-Path $p)) { throw "missing $p" }
}

function Run($exe) {
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path $exe -Leaf) failed ($LASTEXITCODE)" }
}

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
$stage = New-Item -ItemType Directory -Force (Join-Path $out 'apk')

# 1. The native library, always optimised: decoding and drawing in a debug build are far too slow.
$triples = @{ 'arm64-v8a' = 'aarch64-linux-android'; 'x86_64' = 'x86_64-linux-android' }
foreach ($a in $Abi) {
    $t = $triples[$a]
    $var = $t.ToUpper().Replace('-', '_')  # (PowerShell names ignore case: not $T)
    Set-Item "env:CARGO_TARGET_${var}_LINKER" $clang
    # 16 KB pages: Android 15+ devices may use them, and Play requires the alignment.
    Set-Item "env:CARGO_TARGET_${var}_RUSTFLAGS" "-C link-arg=--target=$t$MinSdk -C link-arg=-Wl,-z,max-page-size=16384"
    Run cargo build --release --manifest-path (Join-Path $root '..\Cargo.toml') -p safe-rdp-android --target $t
    $lib = New-Item -ItemType Directory -Force (Join-Path $stage "lib\$a")
    Copy-Item (Join-Path $root "..\target\$t\release\libsaferdp.so") $lib
}

# 2. Resources and manifest.
$flat = New-Item -ItemType Directory -Force (Join-Path $out 'res')
$gen = New-Item -ItemType Directory -Force (Join-Path $out 'gen')
Run "$bt\aapt2.exe" compile --dir (Join-Path $root 'app\res') -o (Join-Path $flat 'res.zip')
$base = Join-Path $out 'base.apk'
$debuggable = [string[]]@(if (-not $Release) { '--debug-mode' })
Run "$bt\aapt2.exe" link -I $androidJar --manifest (Join-Path $root 'app\AndroidManifest.xml') `
    --min-sdk-version $MinSdk --target-sdk-version $TargetSdk --version-code $VersionCode --version-name $VersionName `
    --java $gen -o $base (Join-Path $flat 'res.zip') @debuggable

# 3. Java, against the platform only; R8 shrinks and optimises a release build.
$classes = New-Item -ItemType Directory -Force (Join-Path $out 'classes')
$sources = @(Get-ChildItem (Join-Path $root 'app\java'), $gen -Recurse -Filter *.java | ForEach-Object FullName)
# (core-lambda-stubs: the LambdaMetafactory javac compiles lambdas against; d8 desugars them.)
Run "$java\javac.exe" -source 8 -target 8 -bootclasspath "$androidJar;$bt\core-lambda-stubs.jar" '-Xlint:-options' -encoding UTF-8 -d $classes @sources
$classFiles = @(Get-ChildItem $classes -Recurse -Filter *.class | ForEach-Object FullName)
$dex = New-Item -ItemType Directory -Force (Join-Path $out 'dex')
if ($Release) {
    Run "$java\java.exe" -cp "$bt\lib\d8.jar" com.android.tools.r8.R8 --release --min-api $MinSdk --lib $androidJar `
        --pg-conf (Join-Path $root 'app\r8.pro') --output $dex @classFiles
} else {
    Run "$java\java.exe" -cp "$bt\lib\d8.jar" com.android.tools.r8.D8 --debug --min-api $MinSdk --lib $androidJar --output $dex @classFiles
}
Copy-Item (Join-Path $dex 'classes.dex') $stage

# 4. Into the APK: the libraries stored uncompressed, so the system maps them straight from it.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($base, 'Update')
try {
    foreach ($f in Get-ChildItem $stage -Recurse -File) {
        $name = $f.FullName.Substring($stage.FullName.Length + 1).Replace('\', '/')
        $level = if ($name.EndsWith('.so')) { 'NoCompression' } else { 'Optimal' }
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $name, $level)
    }
} finally { $zip.Dispose() }
$aligned = Join-Path $out 'aligned.apk'
Run "$bt\zipalign.exe" -P 16 -f 4 $base $aligned

# 5. Signed: debug builds with a key made for this checkout, release builds with yours.
$apk = Join-Path $out 'safe-rdp.apk'
if ($Release) {
    if (-not $env:SAFERDP_KEYSTORE) { throw 'set SAFERDP_KEYSTORE to your release keystore (apksigner asks for its password)' }
    Run "$bt\apksigner.bat" sign --ks $env:SAFERDP_KEYSTORE --out $apk $aligned
} else {
    $ks = Join-Path $root 'build\debug.keystore'
    if (-not (Test-Path $ks)) {
        Run "$java\keytool.exe" -genkeypair -keystore $ks -storepass android -keypass android -alias debug `
            -keyalg EC -groupname secp256r1 -validity 10000 -dname 'CN=safe-rdp debug'
    }
    Run "$bt\apksigner.bat" sign --ks $ks --ks-pass pass:android --ks-key-alias debug --out $apk $aligned
}
Remove-Item $base, $aligned
Write-Host "built $apk"
