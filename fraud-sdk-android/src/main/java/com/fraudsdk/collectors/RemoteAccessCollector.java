package com.fraudsdk.collectors;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.provider.Settings;
import android.view.Display;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Remote-access / screen-sharing detection — the on-device-fraud (ODF) signal.
 *
 * There is no reliable "AnyDesk is running" API before Android 15, so this
 * detects the EFFECT, not the app: a screen-share tool spins up a virtual
 * display (MediaProjection / VirtualDisplay), and remote-control tools drive
 * the app through an accessibility service. We report "likely", and only name
 * a tool when the accessibility denylist actually matches a package.
 *
 * Snapshot-style like {@link CallSignalCollector}: cheap, synchronous, and
 * re-sampled on business events (a screen-share usually starts right before
 * the transfer). Never throws.
 */
public final class RemoteAccessCollector {

    private RemoteAccessCollector() {}

    // Known remote-control / screen-share accessibility packages. Effect
    // detection (virtual display) is primary; this just adds attribution.
    private static final String[] REMOTE_CONTROL_PKGS = {
            "com.anydesk", "com.teamviewer", "com.rustdesk",
            "com.sand.airdroid", "com.microsoft.rdc", "com.splashtop",
    };

    public static JSONObject snapshot(Context app) {
        JSONObject o = new JSONObject();
        try {
            // 1. Extra / virtual displays — screen mirroring or capture active.
            JSONArray names = new JSONArray();
            int extra = 0;
            DisplayManager dm = (DisplayManager) app.getSystemService(Context.DISPLAY_SERVICE);
            if (dm != null) {
                for (Display d : dm.getDisplays()) {
                    if (d.getDisplayId() == Display.DEFAULT_DISPLAY) continue;
                    extra++;
                    names.put(String.valueOf(d.getName()));
                }
            }
            o.put("extraDisplays", extra);
            if (extra > 0) o.put("displayNames", names);

            // 2. Accessibility services matched against the remote-control denylist.
            JSONArray matches = new JSONArray();
            boolean accessibilitySuspect = false;
            String setting = Settings.Secure.getString(app.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (setting != null && !setting.isEmpty()) {
                for (String svc : setting.split(":")) {
                    String pkg = svc.indexOf('/') > 0 ? svc.substring(0, svc.indexOf('/')) : svc;
                    String lower = pkg.toLowerCase();
                    for (String bad : REMOTE_CONTROL_PKGS) {
                        if (lower.contains(bad)) {
                            matches.put(pkg);
                            accessibilitySuspect = true;
                            break;
                        }
                    }
                }
            }
            o.put("accessibilitySuspect", accessibilitySuspect);
            if (matches.length() > 0) o.put("accessibilityMatches", matches);

            // 3. Convenience roll-up for the scoring engine.
            o.put("screenShareLikely", extra > 0);
        } catch (Exception ignored) {}
        return o;
    }

    /** True if any snapshot field indicates a remote-access session. */
    public static boolean isSuspect(JSONObject snap) {
        return snap.optBoolean("screenShareLikely", false)
                || snap.optBoolean("accessibilitySuspect", false);
    }
}
