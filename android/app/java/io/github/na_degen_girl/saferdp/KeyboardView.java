package io.github.na_degen_girl.saferdp;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.os.Handler;
import android.os.Looper;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A PC keyboard drawn by the app. Keys go to the host by position (Linux evdev codes, turned into
 * scancodes natively), so the host's layout and input method decide the characters, Hangul
 * included (the 한/영 key switches it). It is no input method: nothing typed passes through a
 * keyboard app, its dictionary or its cloud.
 *
 * Shift, Ctrl, Alt and Win stick: a tap holds them for the next key, a second tap locks them, a
 * third lets go. Held keys repeat, as injected keys do not repeat on the host by themselves.
 */
final class KeyboardView extends View {
    interface Sink {
        void key(int evdev, boolean down);
    }

    private static final int SHIFT = 42, RSHIFT = 54, CTRL = 29, ALT = 56, META = 125, FN = -1;

    /** A key: label, evdev code (FN switches the layer) and width in key units. */
    private static final class Key {
        final String label;
        final int code;
        final float width;
        final RectF box = new RectF();

        Key(String label, int code, float width) {
            this.label = label;
            this.code = code;
            this.width = width;
        }
    }

    private static Key k(String label, int code) {
        return new Key(label, code, 1);
    }

    private static Key k(String label, int code, float width) {
        return new Key(label, code, width);
    }

    private static Key[][] letters() {
        return new Key[][] {
            {k("Esc", 1), k("`", 41), k("1", 2), k("2", 3), k("3", 4), k("4", 5), k("5", 6), k("6", 7), k("7", 8), k("8", 9), k("9", 10), k("0", 11), k("-", 12), k("=", 13), k("⌫", 14, 1.5f)},
            {k("Tab", 15, 1.5f), k("q", 16), k("w", 17), k("e", 18), k("r", 19), k("t", 20), k("y", 21), k("u", 22), k("i", 23), k("o", 24), k("p", 25), k("[", 26), k("]", 27), k("\\", 43)},
            {k("Caps", 58, 1.75f), k("a", 30), k("s", 31), k("d", 32), k("f", 33), k("g", 34), k("h", 35), k("j", 36), k("k", 37), k("l", 38), k(";", 39), k("'", 40), k("Enter", 28, 1.75f)},
            {k("Shift", SHIFT, 2.25f), k("z", 44), k("x", 45), k("c", 46), k("v", 47), k("b", 48), k("n", 49), k("m", 50), k(",", 51), k(".", 52), k("/", 53), k("↑", 103), k("Shift", RSHIFT, 1.25f)},
            {k("Ctrl", CTRL, 1.25f), k("Win", META, 1.25f), k("Alt", ALT, 1.25f), k("한/영", 122, 1.25f), k("", 57, 4.5f), k("한자", 123), k("Fn", FN), k("←", 105), k("↓", 108), k("→", 106)},
        };
    }

    private static Key[][] functions() {
        return new Key[][] {
            {k("Esc", 1), k("F1", 59), k("F2", 60), k("F3", 61), k("F4", 62), k("F5", 63), k("F6", 64), k("F7", 65), k("F8", 66), k("F9", 67), k("F10", 68), k("F11", 87), k("F12", 88)},
            {k("PrtSc", 99, 1.5f), k("ScrLk", 70, 1.5f), k("Pause", 119, 1.5f), k("Ins", 110), k("Home", 102), k("PgUp", 104), k("Num", 69), k("Menu", 127, 1.5f)},
            {k("Tab", 15, 1.5f), k("Del", 111), k("End", 107), k("PgDn", 109), k("Enter", 28, 1.5f), k("⌫", 14, 1.5f)},
            {k("Shift", SHIFT, 2.25f), k("↑", 103), k("Shift", RSHIFT, 1.25f)},
            {k("Ctrl", CTRL, 1.25f), k("Win", META, 1.25f), k("Alt", ALT, 1.25f), k("", 57, 4.5f), k("Fn", FN), k("←", 105), k("↓", 108), k("→", 106)},
        };
    }

    /** Dubeolsik jamo on the letter keys, for a Korean host input method. */
    private static final Map<Integer, String> JAMO = new HashMap<>();

    static {
        String keys = "qwertyuiopasdfghjklzxcvbnm";
        String jamo = "ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔㅁㄴㅇㄹㅎㅗㅓㅏㅣㅋㅌㅊㅍㅠㅜㅡ";
        int[] codes = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35, 36, 37, 38, 44, 45, 46, 47, 48, 49, 50};
        for (int i = 0; i < keys.length(); i++) JAMO.put(codes[i], String.valueOf(jamo.charAt(i)));
    }

    private enum Sticky { OFF, ONCE, LOCKED }

    private final Sink sink;
    private final boolean korean = Locale.getDefault().getLanguage().equals("ko");
    private Key[][] rows = letters();
    private boolean fnLayer;
    private final Map<Integer, Sticky> mods = new HashMap<>();
    /** Keys down, by pointer id. */
    private final Map<Integer, Key> down = new HashMap<>();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Map<Integer, Runnable> repeats = new HashMap<>();
    private final Paint keyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint subPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final float density;

    KeyboardView(Context c, Sink sink) {
        super(c);
        this.sink = sink;
        density = c.getResources().getDisplayMetrics().density;
        textPaint.setColor(0xffffffff);
        textPaint.setTextAlign(Paint.Align.CENTER);
        subPaint.setColor(0xff9ad0b8);
        subPaint.setTextAlign(Paint.Align.RIGHT);
        setBackgroundColor(0xf0202428);
        setHapticFeedbackEnabled(true);
    }

    @Override
    protected void onMeasure(int w, int h) {
        int width = MeasureSpec.getSize(w);
        // Five rows: about 44 dp each, less in landscape so the remote screen keeps most of the height.
        int screenH = getResources().getDisplayMetrics().heightPixels;
        int height = Math.min(Math.round(5 * 44 * density), screenH * 2 / 5);
        setMeasuredDimension(width, height);
    }

    private void layout() {
        float rowH = (float) getHeight() / rows.length;
        float gap = 2 * density;
        for (int r = 0; r < rows.length; r++) {
            float units = 0;
            for (Key key : rows[r]) units += key.width;
            float unit = getWidth() / Math.max(units, 15f);
            float x = (getWidth() - unit * units) / 2;
            for (Key key : rows[r]) {
                key.box.set(x + gap, r * rowH + gap, x + key.width * unit - gap, (r + 1) * rowH - gap);
                x += key.width * unit;
            }
        }
    }

    @Override
    protected void onDraw(Canvas canvas) {
        layout();
        float rowH = (float) getHeight() / rows.length;
        textPaint.setTextSize(Math.min(rowH * 0.38f, 18 * density));
        subPaint.setTextSize(Math.min(rowH * 0.26f, 12 * density));
        for (Key[] row : rows) {
            for (Key key : row) {
                Sticky s = mods.get(key.code);
                boolean pressed = down.containsValue(key) || (key.code == FN && fnLayer);
                int color = pressed ? 0xff5a6570 : s == Sticky.LOCKED ? 0xff2f7d5b : s == Sticky.ONCE ? 0xff3c5a78 : 0xff3a4046;
                keyPaint.setColor(color);
                canvas.drawRoundRect(key.box, 5 * density, 5 * density, keyPaint);
                float cy = key.box.centerY() - (textPaint.descent() + textPaint.ascent()) / 2;
                canvas.drawText(key.label, key.box.centerX(), cy, textPaint);
                String jamo = korean ? JAMO.get(key.code) : null;
                if (jamo != null && !fnLayer) {
                    canvas.drawText(jamo, key.box.right - 4 * density, key.box.top - subPaint.ascent() + 2 * density, subPaint);
                }
            }
        }
    }

    private Key at(float x, float y) {
        for (Key[] row : rows) for (Key key : row) if (key.box.contains(x, y)) return key;
        return null;
    }

    private static boolean isMod(int code) {
        return code == SHIFT || code == RSHIFT || code == CTRL || code == ALT || code == META;
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        int i = e.getActionIndex();
        int id = e.getPointerId(i);
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_POINTER_DOWN:
                press(id, at(e.getX(i), e.getY(i)));
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_POINTER_UP:
                release(id);
                break;
            case MotionEvent.ACTION_CANCEL:
                for (Integer p : new ArrayList<>(down.keySet())) release(p);
                break;
            default:
                break;
        }
        invalidate();
        return true;
    }

    private void press(int id, Key key) {
        if (key == null) return;
        performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
        if (key.code == FN) {
            fnLayer = !fnLayer;
            rows = fnLayer ? functions() : letters();
            return;
        }
        if (isMod(key.code)) {
            Sticky s = mods.getOrDefault(key.code, Sticky.OFF);
            switch (s) {
                case OFF:
                    sink.key(key.code, true);
                    mods.put(key.code, Sticky.ONCE);
                    break;
                case ONCE:
                    mods.put(key.code, Sticky.LOCKED);
                    break;
                case LOCKED:
                    sink.key(key.code, false);
                    mods.remove(key.code);
                    break;
            }
            return;
        }
        down.put(id, key);
        sink.key(key.code, true);
        Runnable r = new Runnable() {
            @Override
            public void run() {
                if (down.get(id) != key) return;
                sink.key(key.code, true);
                handler.postDelayed(this, 45);
            }
        };
        repeats.put(id, r);
        handler.postDelayed(r, 420);
    }

    private void release(int id) {
        Runnable r = repeats.remove(id);
        if (r != null) handler.removeCallbacks(r);
        Key key = down.remove(id);
        if (key == null) return;
        sink.key(key.code, false);
        // One-shot modifiers end with the key they modified.
        List<Integer> once = new ArrayList<>();
        for (Map.Entry<Integer, Sticky> m : mods.entrySet()) if (m.getValue() == Sticky.ONCE) once.add(m.getKey());
        for (int code : once) {
            sink.key(code, false);
            mods.remove(code);
        }
    }

    /** Lets go of everything (the keyboard is hidden or the app left). */
    void releaseAll() {
        for (Integer p : new ArrayList<>(down.keySet())) release(p);
        for (int code : new ArrayList<>(mods.keySet())) sink.key(code, false);
        mods.clear();
        invalidate();
    }
}
