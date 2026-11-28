package io.github.na_degen_girl.saferdp;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.List;

/**
 * The keys in the Keystore: imported from the clipboard or a QR code, shown only by fingerprint,
 * deleted. The key text never goes into a text field, so no keyboard app sees it.
 */
public final class KeysActivity extends Activity {
    static final int SCAN = 1;
    private static final int CAMERA = 2;
    private LinearLayout list;
    private CheckBox auth;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Native.load();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        setTitle(R.string.keys);
        LinearLayout root = Ui.column(this);
        Ui.pad(root, 16);
        root.addView(Ui.text(this, getString(R.string.keys_explained), 14));
        list = Ui.column(this);
        root.addView(list, Ui.wide());
        auth = new CheckBox(this);
        auth.setText(R.string.key_needs_auth);
        KeyguardManager km = getSystemService(KeyguardManager.class);
        boolean secure = km != null && km.isDeviceSecure();
        auth.setChecked(secure);
        auth.setEnabled(secure);
        if (!secure) auth.setText(getString(R.string.key_needs_auth) + "\n" + getString(R.string.no_screen_lock));
        root.addView(auth, Ui.wide());
        LinearLayout buttons = Ui.row(this);
        buttons.addView(Ui.button(this, getString(R.string.import_clipboard), v -> importClipboard()), Ui.weighted());
        buttons.addView(Ui.button(this, getString(R.string.import_qr), v -> scan()), Ui.weighted());
        root.addView(buttons, Ui.wide());
        ScrollView scroll = new ScrollView(this);
        scroll.setFitsSystemWindows(true);
        scroll.addView(root);
        setContentView(scroll);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private void refresh() {
        list.removeAllViews();
        List<String> aliases;
        try {
            aliases = KeyVault.aliases();
        } catch (Exception e) {
            Ui.alert(this, getString(R.string.keys), Ui.why(e));
            return;
        }
        if (aliases.isEmpty()) list.addView(Ui.text(this, getString(R.string.no_keys), 15));
        for (String a : aliases) {
            LinearLayout item = Ui.row(this);
            Ui.pad(item, 8);
            String lines = getString(R.string.key_fp, KeyVault.fingerprint(a)) + "\n" + getString(R.string.key_where, KeyVault.where(a));
            if (KeyVault.needsUser(a)) lines += "\n" + getString(R.string.key_needs_user);
            TextView t = Ui.text(this, lines, 15);
            item.addView(t, Ui.weighted());
            item.addView(Ui.button(this, getString(R.string.delete), v -> new AlertDialog.Builder(this)
                    .setTitle(R.string.delete_key)
                    .setMessage(getString(R.string.delete_key_explained, KeyVault.fingerprint(a)))
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.delete, (d, w) -> {
                        try {
                            KeyVault.delete(a);
                        } catch (Exception e) {
                            Ui.alert(this, getString(R.string.keys), Ui.why(e));
                        }
                        refresh();
                    })
                    .show()));
            list.addView(item, Ui.wide());
        }
    }

    private void importClipboard() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        ClipData clip = cm.getPrimaryClip();
        CharSequence text = clip != null && clip.getItemCount() > 0 ? clip.getItemAt(0).getText() : null;
        byte[] key = text == null ? null : keyText(text);
        if (key == null) {
            // Something else is copied: it stays.
            Ui.alert(this, getString(R.string.import_clipboard), getString(R.string.clipboard_no_key));
            return;
        }
        // The key leaves the clipboard whatever happens next.
        cm.clearPrimaryClip();
        store(key);
    }

    private static final byte[] KEY_PREFIX = {'s', 'r', 'd', 'p', '1', '-'};

    static boolean startsWithKeyPrefix(byte[] b) {
        if (b == null || b.length < KEY_PREFIX.length) return false;
        for (int i = 0; i < KEY_PREFIX.length; i++) if (b[i] != KEY_PREFIX[i]) return false;
        return true;
    }

    /**
     * The text, trimmed, as bytes if it looks like a key ({@code srdp1-}...), else null. Encoded
     * straight from the characters, so no other String of the key is made.
     */
    static byte[] keyText(CharSequence text) {
        int a = 0, b = text.length();
        while (a < b && Character.isWhitespace(text.charAt(a))) a++;
        while (b > a && Character.isWhitespace(text.charAt(b - 1))) b--;
        if (b - a < KEY_PREFIX.length || b - a > 128) return null;
        byte[] out = new byte[b - a];
        for (int i = a; i < b; i++) {
            char ch = text.charAt(i);
            if (ch < 0x21 || ch > 0x7e) {
                java.util.Arrays.fill(out, (byte) 0);
                return null;
            }
            out[i - a] = (byte) ch;
        }
        if (!startsWithKeyPrefix(out)) {
            java.util.Arrays.fill(out, (byte) 0);
            return null;
        }
        return out;
    }

    /** Parses key text (UTF-8, zeroed here) and stores the key; returns its alias. */
    static String storeKey(byte[] text, boolean auth) throws Exception {
        try {
            return KeyVault.importKey(Native.parseKey(text), auth);
        } finally {
            java.util.Arrays.fill(text, (byte) 0);
        }
    }

    private void store(byte[] text) {
        try {
            stored(storeKey(text, auth.isChecked()));
        } catch (Exception e) {
            Ui.alert(this, getString(R.string.import_failed), Ui.why(e));
        }
        refresh();
    }

    private void stored(String alias) {
        Ui.alert(this, getString(R.string.key_stored), getString(R.string.key_stored_explained, KeyVault.fingerprint(alias), KeyVault.where(alias)));
    }

    private void scan() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.CAMERA}, CAMERA);
            return;
        }
        // The scanner stores the key itself: key text sent back in an Intent would pass through
        // the system's process.
        startActivityForResult(new Intent(this, ScanActivity.class).putExtra("auth", auth.isChecked()), SCAN);
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        if (code == CAMERA && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) scan();
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        if (code == SCAN && result == RESULT_OK && data != null && data.getStringExtra("alias") != null) {
            stored(data.getStringExtra("alias"));
        }
        refresh();
    }
}
