# R8 rules for the release build (android/build.ps1 -Release).

# Registered with RegisterNatives and called from native code by name and signature.
-keep class io.github.na_degen_girl.saferdp.Native { *; }
-keep class io.github.na_degen_girl.saferdp.Crypto { static *; }
-keep class io.github.na_degen_girl.saferdp.KeyVault { static byte[] hmac(byte[], byte[]); }

# Started by name from the manifest.
-keep class io.github.na_degen_girl.saferdp.*Activity { <init>(); }
-keep class io.github.na_degen_girl.saferdp.SessionService { <init>(); }

-dontobfuscate

# The self-test, run with app_process from adb (see SelfTest).
-keep class io.github.na_degen_girl.saferdp.SelfTest { public static void main(java.lang.String[]); }
