package com.fraudsdk.collectors;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;

import com.fraudsdk.SdkConfig;

import org.json.JSONObject;

/**
 * Tiered location. The SDK NEVER requests location permission itself.
 *
 * TIER0: nothing client-side — server derives country/city from IP + MCC/MNC.
 * TIER1: if the HOST APP already holds coarse/fine, read last-known location
 *        and truncate to geohash precision 5 (~5 km) before transmission.
 * TIER2: tenant-enabled fine — geohash precision 7 (~150 m). Tenant owns consent.
 *
 * Raw lat/lon never leaves the device.
 */
public final class LocationCollector {

    private final Context app;
    private final SdkConfig config;

    public LocationCollector(Context app, SdkConfig config) {
        this.app = app;
        this.config = config;
    }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            o.put("tier", config.locationTier.name());
            if (config.locationTier == SdkConfig.LocationTier.TIER0_NONE) return o;
            if (!hasAnyLocationPermission()) return o;   // opportunistic only

            LocationManager lm =
                    (LocationManager) app.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) return o;

            Location best = null;
            for (String provider : lm.getProviders(true)) {
                Location l = lm.getLastKnownLocation(provider);
                if (l != null && (best == null || l.getTime() > best.getTime())) best = l;
            }
            if (best == null) return o;

            int precision =
                    config.locationTier == SdkConfig.LocationTier.TIER2_OPT_IN_FINE ? 7 : 5;
            o.put("geohash", geohash(best.getLatitude(), best.getLongitude(), precision));
            o.put("ageMs", System.currentTimeMillis() - best.getTime());
        } catch (Exception ignored) {}
        return o;
    }

    private boolean hasAnyLocationPermission() {
        return granted(Manifest.permission.ACCESS_COARSE_LOCATION)
                || granted(Manifest.permission.ACCESS_FINE_LOCATION);
    }

    private boolean granted(String p) {
        return app.checkCallingOrSelfPermission(p) == PackageManager.PERMISSION_GRANTED;
    }

    // ---- minimal geohash encoder ----
    private static final String B32 = "0123456789bcdefghjkmnpqrstuvwxyz";

    static String geohash(double lat, double lon, int precision) {
        double[] latR = {-90, 90}, lonR = {-180, 180};
        StringBuilder sb = new StringBuilder();
        boolean even = true;
        int bit = 0, ch = 0;
        while (sb.length() < precision) {
            double mid;
            if (even) {
                mid = (lonR[0] + lonR[1]) / 2;
                if (lon > mid) { ch |= 1 << (4 - bit); lonR[0] = mid; } else lonR[1] = mid;
            } else {
                mid = (latR[0] + latR[1]) / 2;
                if (lat > mid) { ch |= 1 << (4 - bit); latR[0] = mid; } else latR[1] = mid;
            }
            even = !even;
            if (bit < 4) bit++;
            else { sb.append(B32.charAt(ch)); bit = 0; ch = 0; }
        }
        return sb.toString();
    }
}
