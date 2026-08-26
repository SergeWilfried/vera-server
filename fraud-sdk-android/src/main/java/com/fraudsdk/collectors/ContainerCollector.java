package com.fraudsdk.collectors;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Process;

import org.json.JSONObject;

import java.util.regex.Pattern;

/**
 * Is this app instance a CLONE? Java port of the Expo SDK's
 * VeraContainerModule — same fields, same rules.
 *
 * The graph links multi-accounting on install_id, and a cloned container
 * (Dual Apps, Secure Folder, Parallel Space) gets its own data dir and
 * keystore, so it mints its own installId: one handset then presents as two
 * unrelated devices. Measured on a real device — two Android users produced
 * two different install ids from the same APK. This collector reports the
 * clone itself, which is what keeps the device link honest.
 *
 * Detects being cloned rather than the presence of a cloning tool — the same
 * choice RemoteAccessCollector makes (an extra display, not "is AnyDesk
 * installed"): no package denylist, no <queries>, nothing to sidestep by
 * switching tools, and nothing QUERY_ALL_PACKAGES-shaped near the host app's
 * Play listing.
 */
public final class ContainerCollector {

    private final Context app;

    public ContainerCollector(Context app) {
        this.app = app;
    }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            int userId = androidUserId();
            o.put("androidUserId", userId);
            o.put("secondaryUser", userId > 0);

            String basis = dataDirBasis();
            o.put("virtualized", "nested".equals(basis));
            o.put("dataDirBasis", basis);

            // A work profile is ALSO a secondary user, and an MDM-managed
            // handset is legitimate — this is what lets the server tell
            // "corporate profile" from "cloned app" instead of scoring every
            // enterprise device as an evasion.
            o.put("adminPresent", adminPresent());
        } catch (Exception ignored) {}
        return o;
    }

    /** Android packs the user id into the uid: uid / PER_USER_RANGE.
     *  0 is the primary user; a dual-app clone or work profile runs above it. */
    private int androidUserId() {
        try {
            return Process.myUid() / 100000;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * "standard" | "nested" | "unrecognised" | "unavailable".
     *
     * A userspace container rewrites the app's data dir to sit inside the
     * host container's own directory. Only a nested path that still contains
     * our own package counts as a clone: adopted storage, device-encrypted
     * dirs and OEM layouts all deviate from the textbook shape on perfectly
     * ordinary handsets, and a false clone flag would land on real customers.
     */
    private String dataDirBasis() {
        String pkg = app.getPackageName();
        String raw;
        try {
            raw = app.getApplicationInfo().dataDir;
            if (raw == null) return "unavailable";
        } catch (Exception e) {
            return "unavailable";
        }

        // Adopted storage is an ordinary configuration — normalise it away.
        String path = raw.replaceFirst("^/mnt/expand/[0-9a-fA-F-]+", "");
        if (Pattern.matches("^/data/(data|user/\\d+|user_de/\\d+)/" + Pattern.quote(pkg) + "/?$", path)) {
            return "standard";
        }
        if (path.contains("/" + pkg)) return "nested";
        return "unrecognised";
    }

    private boolean adminPresent() {
        try {
            DevicePolicyManager dpm =
                    (DevicePolicyManager) app.getSystemService(Context.DEVICE_POLICY_SERVICE);
            return dpm != null && dpm.getActiveAdmins() != null && !dpm.getActiveAdmins().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}
