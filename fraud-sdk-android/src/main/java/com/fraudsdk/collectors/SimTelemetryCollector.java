package com.fraudsdk.collectors;

import android.Manifest;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * SIM telemetry — the WAEMU-critical signal set.
 * ICCID is unreadable without carrier privileges, so SIM-swap detection =
 * subscription-info diff vs the previous session (simChangedSinceLastSession)
 * corroborated server-side with SIM-age heuristics.
 */
public final class SimTelemetryCollector {

    private static final String PREFS = "fraudsdk";
    private static final String KEY_SIM_PROFILE = "sim_profile_hash";

    private final Context app;

    public SimTelemetryCollector(Context app) { this.app = app; }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            TelephonyManager tm =
                    (TelephonyManager) app.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                o.put("networkOperator", tm.getNetworkOperator());     // MCC+MNC
                o.put("networkOperatorName", tm.getNetworkOperatorName());
                o.put("simOperator", tm.getSimOperator());
                o.put("simState", tm.getSimState());
                o.put("isRoaming", tm.isNetworkRoaming());
                o.put("phoneType", tm.getPhoneType());
            }

            StringBuilder profile = new StringBuilder();
            if (hasPermission(Manifest.permission.READ_PHONE_STATE)
                    && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                SubscriptionManager sub = (SubscriptionManager)
                        app.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
                List<SubscriptionInfo> subs =
                        sub != null ? sub.getActiveSubscriptionInfoList() : null;
                if (subs != null) {
                    o.put("subscriptionCount", subs.size());
                    JSONArray slots = new JSONArray();
                    for (SubscriptionInfo si : subs) {
                        JSONObject s = new JSONObject();
                        s.put("slot", si.getSimSlotIndex());
                        s.put("carrier", String.valueOf(si.getCarrierName()));
                        s.put("mcc", si.getMcc());
                        s.put("mnc", si.getMnc());
                        slots.put(s);
                        profile.append(si.getSimSlotIndex()).append(':')
                               .append(si.getMcc()).append('-').append(si.getMnc())
                               .append(':').append(si.getCarrierName()).append(';');
                    }
                    o.put("slots", slots);
                }
            }

            // SIM-change flag: diff against the profile hash from last session
            SharedPreferences sp = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            String prev = sp.getString(KEY_SIM_PROFILE, null);
            String curr = Integer.toHexString(profile.toString().hashCode());
            o.put("simChangedSinceLastSession", prev != null && !prev.equals(curr));
            sp.edit().putString(KEY_SIM_PROFILE, curr).apply();
        } catch (Exception ignored) {}
        return o;
    }

    private boolean hasPermission(String p) {
        return app.checkCallingOrSelfPermission(p) == PackageManager.PERMISSION_GRANTED;
    }
}
