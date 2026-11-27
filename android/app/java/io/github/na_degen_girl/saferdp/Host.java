package io.github.na_degen_girl.saferdp;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** A saved host and how to connect to it. Kept in the app's private preferences (never backed up). */
final class Host {
    String name = "";
    /** MagicDNS name or Tailscale address, optionally with :port. */
    String address = "";
    /** The Keystore alias of the key to use. */
    String key = "";
    boolean viewOnly;
    boolean clipboard;
    boolean audio;
    boolean privacy;
    /** proto.rs QUALITY_*, or 255 for the host's choice. */
    int quality = 255;
    /** 1 = full resolution, 2..4 = 1/n. */
    int downscale = 1;
    boolean trackpad = true;

    String title() {
        return name.isEmpty() ? address : name;
    }

    JSONObject toJson() throws JSONException {
        return new JSONObject()
                .put("name", name).put("address", address).put("key", key)
                .put("viewOnly", viewOnly).put("clipboard", clipboard).put("audio", audio).put("privacy", privacy)
                .put("quality", quality).put("downscale", downscale).put("trackpad", trackpad);
    }

    static Host fromJson(JSONObject o) {
        Host h = new Host();
        h.name = o.optString("name");
        h.address = o.optString("address");
        h.key = o.optString("key");
        h.viewOnly = o.optBoolean("viewOnly");
        h.clipboard = o.optBoolean("clipboard");
        h.audio = o.optBoolean("audio");
        h.privacy = o.optBoolean("privacy");
        h.quality = o.optInt("quality", 255);
        h.downscale = o.optInt("downscale", 1);
        h.trackpad = o.optBoolean("trackpad", true);
        return h;
    }

    void toIntent(Intent i) {
        try {
            i.putExtra("host", toJson().toString());
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    static Host fromIntent(Intent i) {
        try {
            return fromJson(new JSONObject(i.getStringExtra("host")));
        } catch (JSONException | NullPointerException e) {
            return null;
        }
    }

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("hosts", Context.MODE_PRIVATE);
    }

    static List<Host> load(Context c) {
        List<Host> out = new ArrayList<>();
        try {
            JSONArray a = new JSONArray(prefs(c).getString("list", "[]"));
            for (int i = 0; i < a.length(); i++) out.add(fromJson(a.getJSONObject(i)));
        } catch (JSONException e) {
            // A damaged list is started afresh.
        }
        return out;
    }

    static void save(Context c, List<Host> hosts) {
        JSONArray a = new JSONArray();
        try {
            for (Host h : hosts) a.put(h.toJson());
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
        prefs(c).edit().putString("list", a.toString()).apply();
    }

    /** App-wide settings. */
    static boolean allowCapture(Context c) {
        return prefs(c).getBoolean("allowCapture", false);
    }

    static void setAllowCapture(Context c, boolean on) {
        prefs(c).edit().putBoolean("allowCapture", on).apply();
    }
}
