package com.fraudsdk.collectors;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import com.fraudsdk.SdkConfig;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.security.MessageDigest;

/**
 * App & device integrity heuristics: root, emulator, debug, hooking frameworks,
 * accessibility-service abuse (how most banking trojans in the region operate),
 * developer options. Play Integrity verdict is fetched asynchronously if enabled
 * (client library is compileOnly; wire it in the tenant build).
 */
public final class IntegrityCollector {

    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/xbin/su",
            "/data/local/bin/su", "/su/bin/su"
    };

    private static final String[] HOOK_LIBS = { "frida", "xposed", "substrate" };

    private final Context app;
    private final SdkConfig config;

    public IntegrityCollector(Context app, SdkConfig config) {
        this.app = app;
        this.config = config;
    }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            o.put("rootLikely", checkRoot());
            o.put("emulatorLikely", checkEmulator());
            o.put("debuggable", isDebuggable());
            o.put("devOptionsEnabled", devOptionsEnabled());
            o.put("hookingFramework", checkHooking());
            o.put("signingCertSha256", signingCertHash());
            o.put("accessibilityServices", enabledAccessibilityServices());
            o.put("installerPackage", installerPackage());
            o.put("playIntegrityRequested", config.playIntegrityEnabled);
        } catch (Exception ignored) {}
        return o;
    }

    private boolean checkRoot() {
        try {
            for (String p : SU_PATHS) if (new File(p).exists()) return true;
            String tags = Build.TAGS;
            return tags != null && tags.contains("test-keys");
        } catch (Exception e) { return false; }
    }

    private boolean checkEmulator() {
        String fp = Build.FINGERPRINT, model = Build.MODEL, product = Build.PRODUCT;
        return (fp != null && (fp.startsWith("generic") || fp.contains("emulator")))
                || (model != null && (model.contains("google_sdk") || model.contains("Emulator")))
                || (product != null && product.contains("sdk"))
                || "goldfish".equals(Build.HARDWARE) || "ranchu".equals(Build.HARDWARE);
    }

    private boolean isDebuggable() {
        return (app.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private boolean devOptionsEnabled() {
        try {
            return Settings.Global.getInt(app.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0;
        } catch (Exception e) { return false; }
    }

    private String checkHooking() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = r.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String lib : HOOK_LIBS) if (lower.contains(lib)) { r.close(); return lib; }
            }
            r.close();
        } catch (Exception ignored) {}
        return "";
    }

    @SuppressWarnings("deprecation")
    private String signingCertHash() {
        try {
            PackageInfo pi = app.getPackageManager().getPackageInfo(
                    app.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi.signatures != null && pi.signatures.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] d = md.digest(pi.signatures[0].toByteArray());
                StringBuilder sb = new StringBuilder();
                for (byte b : d) sb.append(String.format("%02x", b));
                return sb.toString();
            }
        } catch (Exception ignored) {}
        return "";
    }

    private JSONArray enabledAccessibilityServices() {
        JSONArray arr = new JSONArray();
        try {
            String setting = Settings.Secure.getString(app.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (setting != null && !setting.isEmpty()) {
                for (String s : setting.split(":")) {
                    int slash = s.indexOf('/');
                    arr.put(slash > 0 ? s.substring(0, slash) : s);   // package names only
                }
            }
        } catch (Exception ignored) {}
        return arr;
    }

    private String installerPackage() {
        try {
            String p = app.getPackageManager()
                    .getInstallerPackageName(app.getPackageName());
            return p != null ? p : "";        // "" = sideloaded — strong signal
        } catch (Exception e) { return ""; }
    }
}
