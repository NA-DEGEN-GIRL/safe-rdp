package io.github.na_degen_girl.saferdp;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.PopupMenu;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** The saved hosts, Tailscale's state and the way to the keys. */
public final class MainActivity extends Activity {
    private static final String TAILSCALE = "com.tailscale.ipn";
    private LinearLayout list;
    private TextView net;
    private View openTailscale;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Native.load();
        LinearLayout root = Ui.column(this);
        Ui.pad(root, 16);
        LinearLayout status = Ui.row(this);
        net = Ui.text(this, "", 14);
        status.addView(net, Ui.weighted());
        openTailscale = Ui.button(this, getString(R.string.open_tailscale), v -> {
            Intent i = getPackageManager().getLaunchIntentForPackage(TAILSCALE);
            if (i != null) startActivity(i);
            else Ui.alert(this, getString(R.string.tailscale), getString(R.string.tailscale_missing));
        });
        status.addView(openTailscale);
        root.addView(status, Ui.wide());
        list = Ui.column(this);
        root.addView(list, Ui.wide());
        LinearLayout buttons = Ui.row(this);
        buttons.addView(Ui.button(this, getString(R.string.add_host), v -> edit(null)), Ui.weighted());
        buttons.addView(Ui.button(this, getString(R.string.keys), v -> startActivity(new Intent(this, KeysActivity.class))), Ui.weighted());
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

    /** This device's Tailscale IPv4 address, or null. Carriers hand out 100.64.0.0/10 too, so the
     *  interface must also hold an address of Tailscale's own IPv6 range. */
    static String tailscaleAddress() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp()) continue;
                String v4 = null;
                boolean tailscale = false;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    byte[] b = a.getAddress();
                    if (a instanceof Inet6Address && (b[0] & 0xff) == 0xfd && (b[1] & 0xff) == 0x7a && (b[2] & 0xff) == 0x11
                            && (b[3] & 0xff) == 0x5c && (b[4] & 0xff) == 0xa1 && (b[5] & 0xff) == 0xe0) tailscale = true;
                    if (a instanceof Inet4Address && (b[0] & 0xff) == 100 && (b[1] & 0xc0) == 64) v4 = a.getHostAddress();
                }
                if (tailscale && v4 != null) return v4;
            }
        } catch (Exception e) {
            // Unknown: reported as off.
        }
        return null;
    }

    private void refresh() {
        String ts = tailscaleAddress();
        net.setText(ts != null ? getString(R.string.tailscale_on, ts) : getString(R.string.tailscale_off));
        openTailscale.setVisibility(ts != null ? View.GONE : View.VISIBLE);
        list.removeAllViews();
        List<Host> hosts = Host.load(this);
        if (hosts.isEmpty()) {
            TextView t = Ui.text(this, getString(R.string.no_hosts), 15);
            Ui.pad(t, 12);
            list.addView(t);
        }
        for (int i = 0; i < hosts.size(); i++) {
            final int index = i;
            Host h = hosts.get(i);
            LinearLayout item = Ui.column(this);
            Ui.pad(item, 12);
            item.addView(Ui.title(this, h.title()));
            String detail = h.name.isEmpty() ? "" : h.address + "  ";
            detail += getString(R.string.key_fp, h.key.isEmpty() ? "-" : KeyVault.fingerprint(h.key));
            item.addView(Ui.text(this, detail, 13));
            item.setBackgroundResource(android.R.drawable.list_selector_background);
            item.setOnClickListener(v -> connect(h));
            item.setOnLongClickListener(v -> {
                PopupMenu m = new PopupMenu(this, v);
                m.getMenu().add(0, 1, 0, R.string.edit);
                m.getMenu().add(0, 2, 0, R.string.delete);
                m.setOnMenuItemClickListener(mi -> {
                    if (mi.getItemId() == 1) edit(index);
                    else {
                        List<Host> all = Host.load(this);
                        all.remove(index);
                        Host.save(this, all);
                        refresh();
                    }
                    return true;
                });
                m.show();
                return true;
            });
            list.addView(item, Ui.wide());
        }
    }

    private void connect(Host h) {
        if (h.key.isEmpty()) {
            Ui.alert(this, h.title(), getString(R.string.choose_key_first));
            return;
        }
        Intent i = new Intent(this, SessionActivity.class);
        h.toIntent(i);
        startActivity(i);
    }

    private static int indexOf(int[] values, int v) {
        for (int i = 0; i < values.length; i++) if (values[i] == v) return i;
        return 0;
    }

    /** Adds a host (null) or edits saved host {@code index}. */
    private void edit(Integer index) {
        List<Host> hosts = Host.load(this);
        Host h = index == null ? new Host() : hosts.get(index);
        LinearLayout form = Ui.column(this);
        Ui.pad(form, 16);
        EditText address = new EditText(this);
        address.setHint(R.string.address_hint);
        address.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        address.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        address.setText(h.address);
        EditText name = new EditText(this);
        name.setHint(R.string.name_hint);
        name.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        name.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        name.setText(h.name);
        form.addView(address, Ui.wide());
        form.addView(name, Ui.wide());

        List<String> aliases = new ArrayList<>();
        try {
            aliases = KeyVault.aliases();
        } catch (Exception e) {
            // Shown as no keys.
        }
        List<String> labels = new ArrayList<>();
        for (String a : aliases) labels.add(getString(R.string.key_fp, KeyVault.fingerprint(a)));
        if (aliases.isEmpty()) labels.add(getString(R.string.no_keys_short));
        Spinner key = new Spinner(this);
        key.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels));
        key.setSelection(Math.max(0, aliases.indexOf(h.key)));
        form.addView(Ui.text(this, getString(R.string.key), 13));
        form.addView(key, Ui.wide());

        final int[] qualityValues = {255, 0, 1, 2};
        Spinner quality = new Spinner(this);
        quality.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item,
                new String[] {getString(R.string.quality_host), getString(R.string.quality_lossless), getString(R.string.quality_balanced), getString(R.string.quality_low)}));
        quality.setSelection(indexOf(qualityValues, h.quality));
        form.addView(Ui.text(this, getString(R.string.quality), 13));
        form.addView(quality, Ui.wide());
        Spinner scale = new Spinner(this);
        scale.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, new String[] {"100%", "1/2", "1/3", "1/4"}));
        scale.setSelection(Math.max(0, Math.min(3, h.downscale - 1)));
        form.addView(Ui.text(this, getString(R.string.scale), 13));
        form.addView(scale, Ui.wide());

        CheckBox trackpad = check(form, R.string.trackpad_mode, h.trackpad);
        CheckBox viewOnly = check(form, R.string.view_only, h.viewOnly);
        CheckBox clipboard = check(form, R.string.share_clipboard, h.clipboard);
        CheckBox audio = check(form, R.string.play_sound, h.audio);
        CheckBox privacy = check(form, R.string.privacy_mode, h.privacy);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(form);
        final List<String> keys = aliases;
        new AlertDialog.Builder(this)
                .setTitle(index == null ? R.string.add_host : R.string.edit)
                .setView(scroll)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.save, (d, w) -> {
                    h.address = address.getText().toString().trim();
                    h.name = name.getText().toString().trim();
                    if (h.address.isEmpty()) return;
                    h.key = keys.isEmpty() ? "" : keys.get(key.getSelectedItemPosition());
                    h.quality = qualityValues[quality.getSelectedItemPosition()];
                    h.downscale = scale.getSelectedItemPosition() + 1;
                    h.trackpad = trackpad.isChecked();
                    h.viewOnly = viewOnly.isChecked();
                    h.clipboard = clipboard.isChecked();
                    h.audio = audio.isChecked();
                    h.privacy = privacy.isChecked();
                    if (index == null) hosts.add(h);
                    Host.save(this, hosts);
                    refresh();
                })
                .show();
    }

    private CheckBox check(LinearLayout form, int label, boolean on) {
        CheckBox c = new CheckBox(this);
        c.setText(label);
        c.setChecked(on);
        form.addView(c, Ui.wide());
        return c;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, R.string.keys);
        menu.add(0, 2, 0, R.string.allow_capture).setCheckable(true).setChecked(Host.allowCapture(this));
        menu.add(0, 3, 0, R.string.log);
        menu.add(0, 4, 0, R.string.self_test);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case 1:
                startActivity(new Intent(this, KeysActivity.class));
                return true;
            case 2:
                boolean on = !item.isChecked();
                item.setChecked(on);
                Host.setAllowCapture(this, on);
                if (on) Ui.alert(this, getString(R.string.allow_capture), getString(R.string.allow_capture_warning));
                return true;
            case 3:
                showText(getString(R.string.log), Ui.utf8(Native.log()));
                return true;
            case 4:
                new Thread(() -> {
                    String r;
                    try {
                        r = Ui.utf8(Native.selfTest());
                    } catch (RuntimeException e) {
                        r = Ui.why(e);
                    }
                    final String text = r;
                    runOnUiThread(() -> showText(getString(R.string.self_test), text));
                }).start();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void showText(String title, String text) {
        TextView t = Ui.text(this, text.isEmpty() ? "-" : text, 12);
        t.setTypeface(android.graphics.Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        Ui.pad(t, 16);
        ScrollView s = new ScrollView(this);
        s.addView(t);
        new AlertDialog.Builder(this).setTitle(title).setView(s).setPositiveButton(android.R.string.ok, null).show();
    }
}
