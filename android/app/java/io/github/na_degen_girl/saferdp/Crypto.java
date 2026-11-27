package io.github.na_degen_girl.saferdp;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The crypto primitives of the native session (src/crypto/jca.rs), from the platform's provider
 * (Conscrypt). Called from native code only. Data comes as direct buffers over native memory, which
 * Conscrypt hashes and seals in place.
 */
final class Crypto {
    private Crypto() {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static ECParameterSpec p256;

    /** An exception's text for the native side. */
    static byte[] describe(Throwable t) {
        return t.toString().getBytes(StandardCharsets.UTF_8);
    }

    static void random(byte[] out) {
        RANDOM.nextBytes(out);
    }

    static Object digest() throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256");
    }

    static void digestUpdate(Object md, ByteBuffer data) {
        ((MessageDigest) md).update(data);
    }

    static byte[] digestFinish(Object md) {
        return ((MessageDigest) md).digest();
    }

    static Object hmac(byte[] key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        // SecretKeySpec refuses an empty key; HMAC pads keys with zeros to the block size, so one
        // zero byte is the same key.
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacSHA256"));
        return mac;
    }

    static void hmacUpdate(Object mac, ByteBuffer data) {
        ((Mac) mac).update(data);
    }

    static byte[] hmacFinish(Object mac) {
        return ((Mac) mac).doFinal();
    }

    private static synchronized ECParameterSpec p256() throws GeneralSecurityException {
        if (p256 == null) {
            p256 = ((ECPublicKey) ((KeyPair) ecdhGenerate()).getPublic()).getParams();
        }
        return p256;
    }

    static Object ecdhGenerate() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return g.generateKeyPair();
    }

    /** X || Y, each 32 bytes big-endian, as a point; the provider checks it is on the curve. */
    private static PublicKey point(byte[] q) throws GeneralSecurityException {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(q, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(q, 32, 64));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256()));
    }

    static Object ecdhFromPrivate(byte[] d, byte[] q) throws GeneralSecurityException {
        KeyFactory f = KeyFactory.getInstance("EC");
        return new KeyPair(point(q), f.generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), p256())));
    }

    private static void unsigned32(BigInteger v, byte[] out, int at) {
        byte[] b = v.toByteArray();
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, out, at + 32 - n, n);
    }

    static byte[] ecdhPublic(Object kp) {
        ECPoint w = ((ECPublicKey) ((KeyPair) kp).getPublic()).getW();
        byte[] out = new byte[64];
        unsigned32(w.getAffineX(), out, 0);
        unsigned32(w.getAffineY(), out, 32);
        return out;
    }

    static byte[] ecdhAgree(Object kp, byte[] peer) throws GeneralSecurityException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(((KeyPair) kp).getPrivate());
        ka.doPhase(point(peer), true);
        return ka.generateSecret();
    }

    /** One AES-256-GCM key and its cipher, initialised anew for each record's nonce. */
    private static final class Aead {
        final SecretKeySpec key;
        final Cipher cipher;

        Aead(byte[] key) throws GeneralSecurityException {
            this.key = new SecretKeySpec(key, "AES");
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
        }
    }

    static Object aead(byte[] key) throws GeneralSecurityException {
        return new Aead(key);
    }

    /** Writes the ciphertext and then the 16-byte tag to {@code out}. */
    static void aeadSeal(Object a, byte[] nonce, byte[] aad, ByteBuffer in, ByteBuffer out) throws GeneralSecurityException {
        Aead x = (Aead) a;
        x.cipher.init(Cipher.ENCRYPT_MODE, x.key, new GCMParameterSpec(128, nonce));
        x.cipher.updateAAD(aad);
        x.cipher.doFinal(in, out);
    }

    /** Decrypts ciphertext and tag into {@code out}; false if the tag does not verify. */
    static boolean aeadOpen(Object a, byte[] nonce, byte[] aad, ByteBuffer in, ByteBuffer out) throws GeneralSecurityException {
        Aead x = (Aead) a;
        x.cipher.init(Cipher.DECRYPT_MODE, x.key, new GCMParameterSpec(128, nonce));
        x.cipher.updateAAD(aad);
        try {
            x.cipher.doFinal(in, out);
            return true;
        } catch (AEADBadTagException e) {
            return false;
        }
    }
}
