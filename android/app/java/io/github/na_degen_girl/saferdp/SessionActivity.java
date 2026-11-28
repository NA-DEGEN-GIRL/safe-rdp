package io.github.na_degen_girl.saferdp;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.SystemClock;
import android.util.SparseIntArray;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.PointerIcon;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.window.OnBackInvokedDispatcher;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A session: the remote screen full screen, a bar of controls behind the button at the top, the
 * PC keyboard at the bottom. While the app is out of sight the session is paused (the host stops
 * sending frames), and it ends after {@link #GRACE_MS} or at once when the screen turns off.
 * {@link SessionService} runs meanwhile, or Android would freeze the app and close the connection.
 */
public final class SessionActivity extends Activity implements SurfaceHolder.Callback {
    /** How long a session outlives the app being left. */
    private static final long GRACE_MS = 30_000;
    private static final long LONG_PRESS_MS = 500;

    // session.rs states and Event kinds.
    private static final int CONNECTING = 0, CONNECTED = 1, RECONNECTING = 2, ENDED = 3;
    private static final int EV_STATUS = 1, EV_HELLO = 2, EV_CURSOR = 3, EV_CLIPBOARD = 4, EV_NOTICE = 5, EV_STATE = 6, EV_STATS = 7, EV_HAPTIC = 8;
    // proto.rs host flags.
    private static final int F_CLIPBOARD = 1, F_VIEW_ONLY = 2, F_SAS = 4, F_AUDIO = 8, F_PRIVACY = 32;

    private Host host;
    /** Read without `lock` only to test for zero; calls with it hold `lock`. */
    private volatile long session;
    /** The dialog showing, dismissed when the screen goes. */
    private AlertDialog dialog;
    private CancellationSignal authCancel;
    private boolean clipListening;
    /** `onNewIntent` is replacing this screen: what the old session still reports is ignored. */
    private boolean recreating;
    private final Object lock = new Object();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private SurfaceView surface;
    private TextView status;
    private TextView stats;
    private HorizontalScrollView bar;
    private LinearLayout barRow;
    private KeyboardView keyboard;
    private boolean trackpad;
    private boolean soundOn;
    private boolean privacyOn;
    private int flags;
    private int monitors;
    private int monitor;
    private boolean ended;
    /** Clipboard text that came from the host, not to be sent back. */
    private String fromHost;
    private boolean receiverOn;

    private final Runnable graceOver = () -> end(null);
    private final Runnable longPress = () -> {
        synchronized (lock) {
            if (session != 0) Native.tick(session, SystemClock.uptimeMillis());
        }
    };

    private final BroadcastReceiver screenOff = new BroadcastReceiver() {
        @Override
        public void onReceive(Context c, Intent i) {
            // A phone put away must not keep a remote session (or a blanked host screen) open.
            end(null);
        }
    };

    private final ClipboardManager.OnPrimaryClipChangedListener clipChanged = this::sendClipboard;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Native.load();
        host = Host.fromIntent(getIntent());
        if (host == null) {
            finish();
            return;
        }
        trackpad = host.trackpad;
        soundOn = host.audio;
        privacyOn = host.privacy;
        boolean capture = Host.allowCapture(this);
        if (!capture) getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setHideOverlayWindows(true);
        setRecentsScreenshotEnabled(false);
        getWindow().setDecorFitsSystemWindows(false);

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);
        surface = new SurfaceView(this) {
            @Override
            public boolean onTouchEvent(MotionEvent e) {
                return onSurfaceTouch(e);
            }

            @Override
            public boolean onGenericMotionEvent(MotionEvent e) {
                return onSurfaceGeneric(e) || super.onGenericMotionEvent(e);
            }
        };
        surface.setSecure(!capture);
        surface.getHolder().addCallback(this);
        surface.setFocusable(true);
        surface.setFocusableInTouchMode(true);
        // Keys from a keyboard leave touch mode, and Android would then tint the focused view.
        surface.setDefaultFocusHighlightEnabled(false);
        root.addView(surface, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        status = Ui.text(this, getString(R.string.connecting, host.title()), 16);
        status.setTextColor(Color.WHITE);
        status.setGravity(Gravity.CENTER);
        Ui.pad(status, 24);
        root.addView(status, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER));

        stats = Ui.text(this, "", 11);
        stats.setTextColor(0xccffffff);
        stats.setBackgroundColor(0x80000000);
        stats.setVisibility(View.GONE);
        root.addView(stats, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP | Gravity.START));

        LinearLayout top = Ui.column(this);
        top.setGravity(Gravity.CENTER_HORIZONTAL);
        bar = new HorizontalScrollView(this);
        bar.setBackgroundColor(0xe0202428);
        barRow = Ui.row(this);
        bar.addView(barRow);
        bar.setVisibility(View.GONE);
        top.addView(bar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        Button handle = Ui.button(this, "⋯", v -> toggleBar());
        handle.setBackgroundColor(0x80202428);
        handle.setTextColor(Color.WHITE);
        handle.setMinHeight(0);
        handle.setMinimumHeight(0);
        handle.setPadding(Ui.dp(this, 18), 0, Ui.dp(this, 18), 0);
        top.addView(handle, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, Ui.dp(this, 28)));
        root.addView(top, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP));

        keyboard = new KeyboardView(this, (code, down) -> {
            synchronized (lock) {
                if (session != 0) Native.key(session, code, down);
            }
        });
        keyboard.setVisibility(View.GONE);
        root.addView(keyboard, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        // Edge to edge: the controls keep clear of a camera cutout and of the system bars when
        // they are swiped in; the remote screen itself uses the whole display.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets cut = insets.getInsets(WindowInsets.Type.displayCutout() | WindowInsets.Type.systemBars());
            top.setPadding(cut.left, cut.top, cut.right, 0);
            keyboard.setPadding(cut.left, 0, cut.right, cut.bottom);
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) stats.getLayoutParams();
            lp.setMargins(cut.left, cut.top, 0, 0);
            stats.setLayoutParams(lp);
            return insets;
        });
        setContentView(root);
        setVolumeControlStream(android.media.AudioManager.STREAM_MUSIC);
        immersive();

        getOnBackInvokedDispatcher().registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::back);
        authenticateThenConnect();
    }

    private void immersive() {
        WindowInsetsController c = getWindow().getInsetsController();
        if (c != null) {
            c.hide(WindowInsets.Type.systemBars());
            c.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
        }
    }

    /** A key that needs the user's presence asks for it first (it then stays usable for a while). */
    private void authenticateThenConnect() {
        boolean needs;
        try {
            needs = KeyVault.needsAuth(host.key);
        } catch (Exception e) {
            showEnded(getString(R.string.key_unusable, Ui.why(e)));
            return;
        }
        if (!needs) {
            connect();
            return;
        }
        BiometricPrompt p = new BiometricPrompt.Builder(this)
                .setTitle(getString(R.string.auth_title))
                .setSubtitle(host.title())
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build();
        authCancel = new CancellationSignal();
        p.authenticate(authCancel, getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                connect();
            }

            @Override
            public void onAuthenticationError(int code, CharSequence msg) {
                if (recreating || isFinishing() || isDestroyed()) return;
                boolean cancelled = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED;
                if (cancelled) finish();
                else showEnded(String.valueOf(msg));
            }
        });
    }

    private void connect() {
        if (recreating || isFinishing() || isDestroyed() || session != 0) return;
        int options = (host.viewOnly ? Native.OPT_VIEW_ONLY : 0) | (host.clipboard ? Native.OPT_CLIPBOARD : 0)
                | (host.audio ? Native.OPT_AUDIO : 0) | (host.privacy ? Native.OPT_PRIVACY : 0);
        float density = getResources().getDisplayMetrics().density;
        long s;
        try {
            s = Native.open(Ui.utf8(host.address), Ui.utf8(host.key), null, options, host.downscale, host.quality, 0xfe, trackpad, density);
        } catch (IllegalStateException e) {
            showEnded(Ui.why(e));
            return;
        }
        synchronized (lock) {
            session = s;
        }
        if (surface.getHolder().getSurface().isValid()) {
            Native.surface(s, surface.getHolder().getSurface());
            Native.surfaceSize(s, surface.getWidth(), surface.getHeight());
        }
        Thread events = new Thread(() -> {
            while (true) {
                byte[] e;
                try {
                    e = Native.nextEvent(s);
                } catch (IllegalStateException ex) {
                    e = null;
                }
                if (e == null) break;
                final byte[] ev = e;
                ui.post(() -> onEvent(ev));
            }
            // The session is over: nobody passes the handle again once it is cleared.
            synchronized (lock) {
                if (session == s) session = 0;
            }
            Native.free(s);
        }, "session-events");
        events.start();
        if (!receiverOn) {
            registerReceiver(screenOff, new IntentFilter(Intent.ACTION_SCREEN_OFF), Context.RECEIVER_NOT_EXPORTED);
            receiverOn = true;
        }
    }

    private void onEvent(byte[] e) {
        if (recreating) return;
        ByteBuffer b = ByteBuffer.wrap(e).order(ByteOrder.LITTLE_ENDIAN);
        int kind = b.get() & 0xff;
        switch (kind) {
            case EV_STATUS: {
                int state = b.get() & 0xff;
                String text = Ui.utf8(java.util.Arrays.copyOfRange(e, 2, e.length));
                if (state == CONNECTED) {
                    status.setVisibility(View.GONE);
                } else if (state == RECONNECTING) {
                    status.setText(getString(R.string.reconnecting, text));
                    status.setVisibility(View.VISIBLE);
                } else if (state == CONNECTING) {
                    status.setText(getString(R.string.connecting, host.title()));
                } else if (state == ENDED) {
                    SessionService.stop();
                    if (text.isEmpty() || isFinishing()) finish();
                    else showEnded(text);
                }
                break;
            }
            case EV_HELLO: {
                flags = b.getInt();
                int w = b.getShort() & 0xffff, h = b.getShort() & 0xffff;
                monitor = b.get() & 0xff;
                monitors = b.get() & 0xff;
                buildBar();
                // A new connection: what the host had is unknown again.
                fromHost = null;
                if ((flags & F_CLIPBOARD) == 0 || !host.clipboard) stopClipboard();
                else startClipboard();
                break;
            }
            case EV_CURSOR:
                surface.setPointerIcon(PointerIcon.getSystemIcon(this, pointerType(b.get() & 0xff)));
                break;
            case EV_CLIPBOARD: {
                String text = Ui.utf8(java.util.Arrays.copyOfRange(e, 1, e.length));
                fromHost = text;
                ClipData clip = ClipData.newPlainText("safe-rdp", text);
                PersistableBundle extras = new PersistableBundle();
                // Kept out of the clipboard preview and keyboard apps' clipboard history.
                extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
                clip.getDescription().setExtras(extras);
                getSystemService(ClipboardManager.class).setPrimaryClip(clip);
                break;
            }
            case EV_NOTICE:
                alert(getString(R.string.host_message), Ui.utf8(java.util.Arrays.copyOfRange(e, 1, e.length)));
                break;
            case EV_STATE: {
                int key = b.get() & 0xff;
                int value = b.getInt();
                if (key == Native.SET_AUDIO) soundOn = value == 1;
                if (key == Native.SET_PRIVACY) privacyOn = value == 1;
                if (key == Native.SET_MONITOR && value != -1) monitor = value;
                if (value == -1) {
                    if (key == Native.SET_AUDIO) alert(getString(R.string.sound), getString(R.string.sound_unavailable));
                    if (key == Native.SET_PRIVACY) alert(getString(R.string.privacy), getString(R.string.privacy_unavailable));
                }
                buildBar();
                break;
            }
            case EV_STATS:
                stats.setText(Ui.utf8(java.util.Arrays.copyOfRange(e, 1, e.length)));
                break;
            case EV_HAPTIC:
                surface.performHapticFeedback(HapticFeedbackConstants.LONG_PRESS);
                break;
            default:
                break;
        }
    }

    private static int pointerType(int cursor) {
        switch (cursor) {
            case 0: return PointerIcon.TYPE_NULL;
            case 2: return PointerIcon.TYPE_TEXT;
            case 3: case 13: return PointerIcon.TYPE_WAIT;
            case 4: return PointerIcon.TYPE_CROSSHAIR;
            case 6: return PointerIcon.TYPE_TOP_LEFT_DIAGONAL_DOUBLE_ARROW;
            case 7: return PointerIcon.TYPE_TOP_RIGHT_DIAGONAL_DOUBLE_ARROW;
            case 8: return PointerIcon.TYPE_HORIZONTAL_DOUBLE_ARROW;
            case 9: return PointerIcon.TYPE_VERTICAL_DOUBLE_ARROW;
            case 10: return PointerIcon.TYPE_ALL_SCROLL;
            case 11: return PointerIcon.TYPE_NO_DROP;
            case 12: return PointerIcon.TYPE_HAND;
            case 14: return PointerIcon.TYPE_HELP;
            default: return PointerIcon.TYPE_ARROW;
        }
    }

    private void showEnded(String why) {
        ended = true;
        status.setVisibility(View.GONE);
        show(new AlertDialog.Builder(this)
                .setTitle(getString(R.string.session_ended, host.title()))
                .setMessage(why)
                .setCancelable(false)
                .setPositiveButton(android.R.string.ok, (d, w) -> finish()));
    }

    /** Shows `b` in place of any dialog showing (none once the screen is going). */
    private void show(AlertDialog.Builder b) {
        if (recreating || isFinishing() || isDestroyed()) return;
        if (dialog != null) dialog.dismiss();
        dialog = b.show();
    }

    private void alert(String title, String message) {
        show(new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton(android.R.string.ok, null));
    }

    // The bar.

    private void toggleBar() {
        bar.setVisibility(bar.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE);
        stats.setVisibility(bar.getVisibility());
    }

    private boolean viewOnly() {
        return host.viewOnly || (flags & F_VIEW_ONLY) != 0;
    }

    private void buildBar() {
        barRow.removeAllViews();
        if (!viewOnly()) {
            barButton(getString(R.string.keyboard), v -> toggleKeyboard());
            barButton(getString(trackpad ? R.string.mode_trackpad : R.string.mode_direct), v -> {
                trackpad = !trackpad;
                command(trackpad ? Native.CMD_TRACKPAD : Native.CMD_DIRECT);
                buildBar();
            });
        }
        barButton(getString(R.string.fit), v -> command(Native.CMD_RESET_VIEW));
        if (monitors > 1) {
            barButton(getString(R.string.monitor), v -> {
                PopupMenu m = new PopupMenu(this, v);
                for (int i = 0; i < monitors; i++) m.getMenu().add(0, i, i, getString(R.string.monitor_n, i + 1)).setCheckable(true).setChecked(i == monitor);
                m.getMenu().add(0, 0xff, monitors, R.string.monitor_all).setCheckable(true).setChecked(monitor == 0xff);
                m.setOnMenuItemClickListener(mi -> set(Native.SET_MONITOR, mi.getItemId()));
                m.show();
            });
        }
        barButton(getString(R.string.quality), v -> {
            PopupMenu m = new PopupMenu(this, v);
            m.getMenu().add(0, 0, 0, R.string.quality_lossless);
            m.getMenu().add(0, 1, 1, R.string.quality_balanced);
            m.getMenu().add(0, 2, 2, R.string.quality_low);
            m.setOnMenuItemClickListener(mi -> set(Native.SET_QUALITY, mi.getItemId()));
            m.show();
        });
        barButton(getString(R.string.scale), v -> {
            PopupMenu m = new PopupMenu(this, v);
            String[] labels = {"100%", "1/2", "1/3", "1/4"};
            for (int i = 0; i < 4; i++) m.getMenu().add(0, i + 1, i, labels[i]);
            m.setOnMenuItemClickListener(mi -> set(Native.SET_DOWNSCALE, mi.getItemId()));
            m.show();
        });
        if (!viewOnly() && (flags & F_SAS) != 0) {
            barButton("Ctrl+Alt+Del", v -> show(new AlertDialog.Builder(this)
                    .setMessage(R.string.send_sas)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(android.R.string.ok, (d, w) -> command(Native.CMD_SAS))));
        }
        if ((flags & F_AUDIO) != 0) {
            barButton(getString(soundOn ? R.string.sound_on : R.string.sound_off), v -> set(Native.SET_AUDIO, soundOn ? 0 : 1));
        }
        if (!viewOnly() && (flags & F_PRIVACY) != 0) {
            barButton(getString(privacyOn ? R.string.privacy_on : R.string.privacy_off), v -> set(Native.SET_PRIVACY, privacyOn ? 0 : 1));
        }
        barButton(getString(R.string.disconnect), v -> end(null));
    }

    private void barButton(String label, View.OnClickListener l) {
        Button b = Ui.button(this, label, l);
        b.setTextColor(Color.WHITE);
        b.setBackgroundColor(Color.TRANSPARENT);
        barRow.addView(b);
    }

    private boolean set(int key, int value) {
        synchronized (lock) {
            if (session != 0) Native.set(session, key, value);
        }
        return true;
    }

    private void command(int cmd) {
        synchronized (lock) {
            if (session != 0) Native.command(session, cmd);
        }
    }

    private void toggleKeyboard() {
        if (keyboard.getVisibility() == View.VISIBLE) {
            keyboard.releaseAll();
            keyboard.setVisibility(View.GONE);
        } else {
            keyboard.setVisibility(View.VISIBLE);
            bar.setVisibility(View.GONE);
            stats.setVisibility(View.GONE);
        }
    }

    private void back() {
        if (keyboard.getVisibility() == View.VISIBLE) {
            toggleKeyboard();
        } else if (bar.getVisibility() == View.VISIBLE) {
            toggleBar();
        } else if (ended || session == 0) {
            finish();
        } else {
            show(new AlertDialog.Builder(this)
                    .setMessage(getString(R.string.disconnect_from, host.title()))
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.disconnect, (d, w) -> end(null)));
        }
    }

    /** Ends the session (and this screen). */
    private void end(String why) {
        synchronized (lock) {
            if (session != 0) Native.close(session);
        }
        if (why == null) finish();
        else showEnded(why);
    }

    // Input.

    private boolean onSurfaceTouch(MotionEvent e) {
        if (isMouse(e)) return onMouse(e);
        long s;
        synchronized (lock) {
            s = session;
            if (s == 0) return true;
            long t = e.getEventTime();
            int i = e.getActionIndex();
            switch (e.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                case MotionEvent.ACTION_POINTER_DOWN:
                    Native.touch(s, 0, e.getPointerId(i), e.getX(i), e.getY(i), t);
                    ui.removeCallbacks(longPress);
                    ui.postDelayed(longPress, LONG_PRESS_MS);
                    break;
                case MotionEvent.ACTION_MOVE:
                    for (int p = 0; p < e.getPointerCount(); p++) Native.touch(s, 1, e.getPointerId(p), e.getX(p), e.getY(p), t);
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_POINTER_UP:
                    Native.touch(s, 2, e.getPointerId(i), e.getX(i), e.getY(i), t);
                    if (e.getActionMasked() == MotionEvent.ACTION_UP) ui.removeCallbacks(longPress);
                    break;
                case MotionEvent.ACTION_CANCEL:
                    Native.touch(s, 3, 0, 0, 0, t);
                    ui.removeCallbacks(longPress);
                    break;
                default:
                    break;
            }
        }
        return true;
    }

    private static boolean isMouse(MotionEvent e) {
        int tool = e.getToolType(0);
        return tool == MotionEvent.TOOL_TYPE_MOUSE || e.isFromSource(InputDevice.SOURCE_MOUSE) && tool != MotionEvent.TOOL_TYPE_FINGER;
    }

    /** Hover and scrolling from a mouse; a stylus hovering over the screen is not one. */
    private boolean onSurfaceGeneric(MotionEvent e) {
        if (e.isFromSource(InputDevice.SOURCE_CLASS_POINTER) && isMouse(e)) return onMouse(e);
        return false;
    }

    private boolean onMouse(MotionEvent e) {
        synchronized (lock) {
            if (session == 0) return true;
            switch (e.getActionMasked()) {
                case MotionEvent.ACTION_HOVER_MOVE:
                case MotionEvent.ACTION_MOVE:
                    Native.mouse(session, 0, e.getX(), e.getY(), e.getButtonState(), 0, 0);
                    break;
                case MotionEvent.ACTION_DOWN:
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_BUTTON_PRESS:
                case MotionEvent.ACTION_BUTTON_RELEASE:
                    Native.mouse(session, 1, e.getX(), e.getY(), e.getButtonState(), 0, 0);
                    break;
                case MotionEvent.ACTION_SCROLL:
                    Native.mouse(session, 2, e.getX(), e.getY(), e.getButtonState(),
                            e.getAxisValue(MotionEvent.AXIS_VSCROLL), e.getAxisValue(MotionEvent.AXIS_HSCROLL));
                    break;
                default:
                    break;
            }
        }
        return true;
    }

    /** Android key codes to evdev codes, for key events that carry no scancode. */
    private static final SparseIntArray KEYCODES = new SparseIntArray();

    static {
        int[][] map = {
            {KeyEvent.KEYCODE_ESCAPE, 1}, {KeyEvent.KEYCODE_GRAVE, 41}, {KeyEvent.KEYCODE_MINUS, 12}, {KeyEvent.KEYCODE_EQUALS, 13},
            {KeyEvent.KEYCODE_DEL, 14}, {KeyEvent.KEYCODE_TAB, 15}, {KeyEvent.KEYCODE_LEFT_BRACKET, 26}, {KeyEvent.KEYCODE_RIGHT_BRACKET, 27},
            {KeyEvent.KEYCODE_ENTER, 28}, {KeyEvent.KEYCODE_CTRL_LEFT, 29}, {KeyEvent.KEYCODE_SEMICOLON, 39}, {KeyEvent.KEYCODE_APOSTROPHE, 40},
            {KeyEvent.KEYCODE_SHIFT_LEFT, 42}, {KeyEvent.KEYCODE_BACKSLASH, 43}, {KeyEvent.KEYCODE_COMMA, 51}, {KeyEvent.KEYCODE_PERIOD, 52},
            {KeyEvent.KEYCODE_SLASH, 53}, {KeyEvent.KEYCODE_SHIFT_RIGHT, 54}, {KeyEvent.KEYCODE_ALT_LEFT, 56}, {KeyEvent.KEYCODE_SPACE, 57},
            {KeyEvent.KEYCODE_CAPS_LOCK, 58}, {KeyEvent.KEYCODE_CTRL_RIGHT, 97}, {KeyEvent.KEYCODE_ALT_RIGHT, 100},
            {KeyEvent.KEYCODE_MOVE_HOME, 102}, {KeyEvent.KEYCODE_DPAD_UP, 103}, {KeyEvent.KEYCODE_PAGE_UP, 104},
            {KeyEvent.KEYCODE_DPAD_LEFT, 105}, {KeyEvent.KEYCODE_DPAD_RIGHT, 106}, {KeyEvent.KEYCODE_MOVE_END, 107},
            {KeyEvent.KEYCODE_DPAD_DOWN, 108}, {KeyEvent.KEYCODE_PAGE_DOWN, 109}, {KeyEvent.KEYCODE_INSERT, 110},
            {KeyEvent.KEYCODE_FORWARD_DEL, 111}, {KeyEvent.KEYCODE_META_LEFT, 125}, {KeyEvent.KEYCODE_META_RIGHT, 126},
            {KeyEvent.KEYCODE_KANA, 122}, {KeyEvent.KEYCODE_EISU, 123},
        };
        for (int[] m : map) KEYCODES.put(m[0], m[1]);
        String letters = "qwertyuiopasdfghjklzxcvbnm";
        int[] codes = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35, 36, 37, 38, 44, 45, 46, 47, 48, 49, 50};
        for (int i = 0; i < letters.length(); i++) KEYCODES.put(KeyEvent.KEYCODE_A + letters.charAt(i) - 'a', codes[i]);
        for (int d = 1; d <= 9; d++) KEYCODES.put(KeyEvent.KEYCODE_0 + d, 1 + d);
        KEYCODES.put(KeyEvent.KEYCODE_0, 11);
        for (int f = 0; f < 10; f++) KEYCODES.put(KeyEvent.KEYCODE_F1 + f, 59 + f);
        KEYCODES.put(KeyEvent.KEYCODE_F11, 87);
        KEYCODES.put(KeyEvent.KEYCODE_F12, 88);
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent e) {
        int code = e.getKeyCode();
        // The system keeps these: volume, the back gesture from a navigation bar, and so on.
        boolean system = code == KeyEvent.KEYCODE_VOLUME_UP || code == KeyEvent.KEYCODE_VOLUME_DOWN || code == KeyEvent.KEYCODE_VOLUME_MUTE
                || code == KeyEvent.KEYCODE_POWER || code == KeyEvent.KEYCODE_HOME || code == KeyEvent.KEYCODE_APP_SWITCH
                || (code == KeyEvent.KEYCODE_BACK && (e.getSource() & InputDevice.SOURCE_KEYBOARD) != InputDevice.SOURCE_KEYBOARD);
        if (system || e.getAction() == KeyEvent.ACTION_MULTIPLE) return super.dispatchKeyEvent(e);
        int evdev = e.getScanCode();
        // No scancode (a virtual keyboard, adb) or one beyond the standard keys: by key code.
        if (evdev == 0 || evdev > 255) evdev = KEYCODES.get(code, 0);
        synchronized (lock) {
            if (evdev != 0 && session != 0) {
                // Held keys come again with a repeat count: the host sees them repeat, as it would.
                Native.key(session, evdev, e.getAction() == KeyEvent.ACTION_DOWN);
                return true;
            }
        }
        return super.dispatchKeyEvent(e);
    }

    // The clipboard: to the host while this screen has the focus (Android lets only the focused
    // app read it), from the host whenever it sends.

    private void startClipboard() {
        // Once: the clipboard keeps one entry per registration, and reconnects hello again.
        if (!clipListening) {
            getSystemService(ClipboardManager.class).addPrimaryClipChangedListener(clipChanged);
            clipListening = true;
        }
        sendClipboard();
    }

    private void stopClipboard() {
        if (clipListening) {
            getSystemService(ClipboardManager.class).removePrimaryClipChangedListener(clipChanged);
            clipListening = false;
        }
    }

    private void sendClipboard() {
        if (!host.clipboard || (flags & F_CLIPBOARD) == 0 || viewOnly() || !hasWindowFocus()) return;
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        ClipDescription d = cm.getPrimaryClipDescription();
        if (d == null || !(d.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN) || d.hasMimeType(ClipDescription.MIMETYPE_TEXT_HTML))) return;
        ClipData clip = cm.getPrimaryClip();
        CharSequence t = clip != null && clip.getItemCount() > 0 ? clip.getItemAt(0).getText() : null;
        if (t == null) return;
        String text = t.toString();
        if (text.equals(fromHost)) return;
        fromHost = text;
        synchronized (lock) {
            if (session != 0) Native.clipboard(session, Ui.utf8(text));
        }
    }

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused) {
            immersive();
            sendClipboard();
        } else {
            keyboard.releaseAll();
            command(Native.CMD_RELEASE_ALL);
        }
    }

    // The surface and the lifecycle.

    @Override
    public void surfaceCreated(SurfaceHolder h) {
        synchronized (lock) {
            if (session != 0) Native.surface(session, h.getSurface());
        }
    }

    @Override
    public void surfaceChanged(SurfaceHolder h, int format, int width, int height) {
        synchronized (lock) {
            if (session != 0) Native.surfaceSize(session, width, height);
        }
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder h) {
        synchronized (lock) {
            if (session != 0) Native.surface(session, null);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        ui.removeCallbacks(graceOver);
        SessionService.stop();
        command(Native.CMD_RESUME);
    }

    @Override
    protected void onStop() {
        super.onStop();
        keyboard.releaseAll();
        command(Native.CMD_PAUSE);
        // Not while the unlock screen is up before a session exists: that is this screen's own doing.
        if (!isFinishing() && session != 0) {
            ui.postDelayed(graceOver, GRACE_MS);
            SessionService.start(this);
        }
    }

    /** Another host (or the same one, with other settings) chosen while this screen exists. */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Host next = Host.fromIntent(intent);
        if (next == null) return;
        try {
            if (host != null && next.toJson().toString().equals(host.toJson().toString()) && session != 0 && !ended) return;
        } catch (org.json.JSONException e) {
            // Taken as another host.
        }
        // The old session's end arrives on the looper before the recreation: it must not finish
        // this screen, nor anything else of the old one run.
        recreating = true;
        ui.removeCallbacksAndMessages(null);
        if (authCancel != null) authCancel.cancel();
        if (dialog != null) {
            dialog.dismiss();
            dialog = null;
        }
        synchronized (lock) {
            if (session != 0) {
                Native.surface(session, null);
                Native.close(session);
            }
        }
        setIntent(intent);
        recreate();
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        if (authCancel != null) authCancel.cancel();
        if (dialog != null) dialog.dismiss();
        stopClipboard();
        if (receiverOn) unregisterReceiver(screenOff);
        SessionService.stop();
        synchronized (lock) {
            if (session != 0) {
                Native.surface(session, null);
                Native.close(session);
            }
        }
        super.onDestroy();
    }
}
