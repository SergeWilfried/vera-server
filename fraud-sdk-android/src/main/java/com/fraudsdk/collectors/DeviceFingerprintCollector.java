package com.fraudsdk.collectors;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.util.DisplayMetrics;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Probabilistic hardware profile. No IMEI/serial (restricted since API 29).
 * Server-side: nearest-neighbor match re-links a device after reinstall.
 */
public final class DeviceFingerprintCollector {

    private final Context app;

    public DeviceFingerprintCollector(Context app) { this.app = app; }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            o.put("manufacturer", Build.MANUFACTURER);
            o.put("model", Build.MODEL);
            o.put("device", Build.DEVICE);
            o.put("board", Build.BOARD);
            o.put("hardware", Build.HARDWARE);
            o.put("androidRelease", Build.VERSION.RELEASE);
            o.put("sdkInt", Build.VERSION.SDK_INT);
            o.put("securityPatch", Build.VERSION.SECURITY_PATCH);
            o.put("supportedAbis", new JSONArray(Build.SUPPORTED_ABIS));

            DisplayMetrics dm = app.getResources().getDisplayMetrics();
            o.put("screenW", dm.widthPixels);
            o.put("screenH", dm.heightPixels);
            o.put("densityDpi", dm.densityDpi);

            SensorManager sm = (SensorManager) app.getSystemService(Context.SENSOR_SERVICE);
            if (sm != null) {
                JSONArray sensors = new JSONArray();
                for (Sensor s : sm.getSensorList(Sensor.TYPE_ALL)) sensors.put(s.getType());
                o.put("sensorTypes", sensors);
            }

            InputMethodManager imm =
                    (InputMethodManager) app.getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) {
                JSONArray imes = new JSONArray();
                List<InputMethodInfo> list = imm.getEnabledInputMethodList();
                for (InputMethodInfo i : list) imes.put(i.getPackageName());
                o.put("keyboards", imes);
            }

            StatFs fs = new StatFs(Environment.getDataDirectory().getPath());
            o.put("totalStorageMb", fs.getTotalBytes() / (1024 * 1024));

            Runtime rt = Runtime.getRuntime();
            o.put("jvmMaxMemMb", rt.maxMemory() / (1024 * 1024));

            o.put("locale", app.getResources().getConfiguration().locale.toString());
            o.put("timezone", java.util.TimeZone.getDefault().getID());
        } catch (Exception ignored) {}
        return o;
    }
}
