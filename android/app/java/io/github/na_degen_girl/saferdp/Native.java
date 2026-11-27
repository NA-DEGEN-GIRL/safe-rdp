package io.github.na_degen_girl.saferdp;

import android.view.Surface;

/** The native library's entry points (android/native/src/natives.rs). Failures raise IllegalStateException. */
final class Native {
    private Native() {}

    /** Loads the library; done once per process, before any other call. */
    static void load() {
        System.loadLibrary("saferdp");
    }

    /** Crypto vectors and a loopback session; one line per group. */
    static native byte[] selfTest();

    /** {@code srdp1-...} text (UTF-8) to the key's 32 bytes. */
    static native byte[] parseKey(byte[] text);

    /** The native side's kept log lines. */
    static native byte[] log();

    /**
     * Connects, authenticates with Keystore key {@code alias} (or key text {@code key}, for tests)
     * and returns what the host said. Blocks.
     */
    static native byte[] probe(byte[] target, byte[] alias, byte[] key);

    /** Reads a QR code in a camera frame's luminance plane: its text, or null. */
    static native byte[] qrDecode(java.nio.ByteBuffer luma, int width, int height, int stride);

    // Sessions (session.rs). A handle stays valid until free().

    static final int OPT_VIEW_ONLY = 1, OPT_CLIPBOARD = 2, OPT_AUDIO = 4, OPT_PRIVACY = 8;

    static native long open(byte[] target, byte[] alias, byte[] key, int options, int downscale, int quality, int monitor, boolean trackpad, float density);

    static native void surface(long s, Surface surface);

    static native void surfaceSize(long s, int width, int height);

    /** kind: 0 down, 1 move, 2 up, 3 cancel. */
    static native void touch(long s, int kind, int id, float x, float y, long timeMs);

    static native void tick(long s, long timeMs);

    /** kind: 0 moved, 1 buttons changed, 2 scrolled (notches). */
    static native void mouse(long s, int kind, float x, float y, int buttons, float vscroll, float hscroll);

    /** A key by its Linux evdev code. */
    static native void key(long s, int evdev, boolean down);

    /** proto.rs SET_* settings. */
    static final int SET_QUALITY = 1, SET_DOWNSCALE = 2, SET_MONITOR = 3, SET_AUDIO = 4, SET_PRIVACY = 5;

    static native void set(long s, int key, int value);

    static final int CMD_SAS = 1, CMD_REFRESH = 2, CMD_RELEASE_ALL = 3, CMD_PAUSE = 4, CMD_RESUME = 5, CMD_RESET_VIEW = 6,
            CMD_TRACKPAD = 7, CMD_DIRECT = 8;

    static native void command(long s, int cmd);

    static native void clipboard(long s, byte[] text);

    /** The next event, waiting for one; null once the session is over. */
    static native byte[] nextEvent(long s);

    static native void close(long s);

    static native void free(long s);
}
