package io.github.na_degen_girl.saferdp;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.UserNotAuthenticatedException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pre-shared keys, kept in the Android Keystore as HMAC-SHA256 keys that cannot be exported. The
 * protocol only ever uses the key as an HMAC key (the handshake's HKDF-Extract and the
 * fingerprint), so once imported the key is used inside the secure hardware and never comes back
 * into this process. Each key's alias is {@code srdp-} + its fingerprint.
 */
final class KeyVault {
    private KeyVault() {}

    private static final String STORE = "AndroidKeyStore";
    private static final String PREFIX = "srdp-";
    private static final byte[] FINGERPRINT_LABEL = "safe-rdp/1 key fingerprint".getBytes(StandardCharsets.US_ASCII);
    /** How long one unlock or biometric check lets a key be used: automatic reconnects within it ask nothing. */
    static final int AUTH_SECONDS = 300;

    private static KeyStore store() throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance(STORE);
            ks.load(null);
            return ks;
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static String hex(byte[] b, int n) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < n; i++) s.append(String.format("%02x", b[i] & 0xff));
        return s.toString();
    }

    /** The fingerprint a key's alias carries (as keys.rs computes it). */
    static String fingerprint(String alias) {
        return alias.substring(PREFIX.length());
    }

    /**
     * Stores 32 key bytes (zeroed here afterwards) and returns the alias. With {@code auth}, using
     * the key needs the device unlocked or a biometric check within {@link #AUTH_SECONDS}.
     */
    static String importKey(Context c, byte[] key, boolean auth) throws GeneralSecurityException {
        try {
            SecretKeySpec spec = new SecretKeySpec(key, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(spec);
            String alias = PREFIX + hex(mac.doFinal(FINGERPRINT_LABEL), 8);
            // Stored again even if a key of that fingerprint is there: with the protection asked
            // for now, and in place of one the system invalidated (new fingerprints enrolled).
            KeyStore ks = store();
            boolean locked = deviceSecure(c);
            try {
                ks.setEntry(alias, new KeyStore.SecretKeyEntry(spec), protection(auth, locked, true));
            } catch (GeneralSecurityException | java.security.ProviderException e) {
                // No StrongBox (reported as StrongBoxUnavailableException, on some devices inside a
                // KeyStoreException): the TEE then. Any other problem shows again below.
                ks.setEntry(alias, new KeyStore.SecretKeyEntry(spec), protection(auth, locked, false));
            }
            return alias;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** Whether the device has a screen lock (a PIN, pattern or password). */
    static boolean deviceSecure(Context c) {
        KeyguardManager km = c.getSystemService(KeyguardManager.class);
        return km != null && km.isDeviceSecure();
    }

    /**
     * With a screen lock, the key works only while the device is unlocked (whoever holds it
     * locked cannot use the key, whatever runs on it); without one that would mean nothing.
     */
    private static KeyProtection protection(boolean auth, boolean screenLock, boolean strongBox) {
        KeyProtection.Builder b = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setUnlockedDeviceRequired(screenLock)
                .setIsStrongBoxBacked(strongBox);
        if (auth) {
            b.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(AUTH_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    .setInvalidatedByBiometricEnrollment(true);
        }
        return b.build();
    }

    /** HMAC-SHA256 under the stored key {@code alias} (UTF-8); called by the native handshake. */
    static byte[] hmac(byte[] alias, byte[] data) throws GeneralSecurityException {
        String name = new String(alias, StandardCharsets.UTF_8);
        java.security.Key k = store().getKey(name, null);
        if (k == null) throw new GeneralSecurityException("no stored key " + name);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(k);
        return mac.doFinal(data);
    }

    /** Whether using {@code alias} needs the user to authenticate first. */
    static boolean needsAuth(String alias) throws GeneralSecurityException {
        try {
            hmac(alias.getBytes(StandardCharsets.UTF_8), FINGERPRINT_LABEL);
            return false;
        } catch (UserNotAuthenticatedException e) {
            return true;
        }
    }

    /** Whether using the key asks for an unlock or a fingerprint (false if unknown). */
    static boolean needsUser(String alias) {
        try {
            return info(alias).isUserAuthenticationRequired();
        } catch (Exception e) {
            return false;
        }
    }

    private static KeyInfo info(String alias) throws GeneralSecurityException {
        SecretKey k = (SecretKey) store().getKey(alias, null);
        if (k == null) throw new GeneralSecurityException("no stored key " + alias);
        return (KeyInfo) SecretKeyFactory.getInstance(k.getAlgorithm(), STORE).getKeySpec(k, KeyInfo.class);
    }

    /** Where the key lives: "StrongBox", "TEE" or "software". */
    static String where(String alias) {
        try {
            KeyInfo info = info(alias);
            if (Build.VERSION.SDK_INT >= 31) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX: return "StrongBox";
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "TEE";
                    case KeyProperties.SECURITY_LEVEL_SOFTWARE: return "software";
                    default: return "unknown";
                }
            }
            return "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    static List<String> aliases() throws GeneralSecurityException {
        List<String> out = new ArrayList<>();
        for (String a : Collections.list(store().aliases())) {
            if (a.startsWith(PREFIX)) out.add(a);
        }
        Collections.sort(out);
        return out;
    }

    static void delete(String alias) throws GeneralSecurityException {
        store().deleteEntry(alias);
    }
}
