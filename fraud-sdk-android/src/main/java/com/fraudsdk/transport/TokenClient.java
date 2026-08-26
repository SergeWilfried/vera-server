package com.fraudsdk.transport;

import com.fraudsdk.SdkConfig;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Server-side session-token minting (POST /v1/collect/token). The app holds
 * no signing key any more — v0.2 minted tokens on-device with the tenant
 * HMAC key, which shipped the tenant secret inside every APK. The native
 * credential is now the per-tenant app key (X-App-Key), which is never
 * served to web visitors and is rotatable per tenant.
 *
 * Call only from the SDK worker thread (blocking network I/O).
 */
public final class TokenClient {
    private TokenClient() {}

    /** Mints a token for (sessionId, userRef); returns null on any failure. */
    public static String mint(SdkConfig config, String sessionId,
                              String installId, String userRef) {
        // disconnect() lives in finally: if the write or read throws mid-flight
        // (exactly what flaky field networks produce), an early return path
        // would otherwise leak the connection.
        HttpURLConnection c = null;
        try {
            JSONObject body = new JSONObject();
            body.put("sessionId", sessionId);
            body.put("installId", installId);
            if (userRef != null) body.put("userRef", userRef);
            byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);

            c = (HttpURLConnection)
                    new URL(config.collectorBaseUrl + "/v1/collect/token").openConnection();
            c.setConnectTimeout(10_000);
            c.setReadTimeout(10_000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            c.setRequestProperty("X-Tenant-Id", config.tenantId);
            c.setRequestProperty("X-App-Key", config.appKey);
            try (OutputStream os = c.getOutputStream()) { os.write(payload); }

            if (c.getResponseCode() != 200) return null;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (InputStream is = c.getInputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0 && bos.size() < 64_000) bos.write(buf, 0, n);
            }
            String token = new JSONObject(bos.toString("UTF-8")).optString("token", "");
            return token.isEmpty() ? null : token;
        } catch (Exception e) {
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }
}
