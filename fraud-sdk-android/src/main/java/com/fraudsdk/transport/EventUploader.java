package com.fraudsdk.transport;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Base64;

import com.fraudsdk.SdkConfig;
import com.fraudsdk.session.SessionManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Periodic batched upload: NDJSON -> gzip -> HMAC-signed POST. Exponential backoff. */
public final class EventUploader {

    private final Context app;
    private final SdkConfig config;
    private final EventQueue queue;
    private final SessionManager sessions;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "fraudsdk-uploader");
                t.setDaemon(true);
                return t;
            });

    private volatile long backoffMs = 0;

    public EventUploader(Context app, SdkConfig config, EventQueue queue, SessionManager sessions) {
        this.app = app;
        this.config = config;
        this.queue = queue;
        this.sessions = sessions;
    }

    public void start() {
        scheduler.scheduleWithFixedDelay(this::uploadOnce,
                config.uploadIntervalMs, config.uploadIntervalMs, TimeUnit.MILLISECONDS);
    }

    public void flushAsync() {
        scheduler.execute(this::uploadOnce);
    }

    private void uploadOnce() {
        try {
            if (backoffMs > 0) { Thread.sleep(Math.min(backoffMs, 60_000)); }
            if (!isConnected()) return;

            List<String> batch = queue.peek(config.maxBatchSize);
            if (batch.isEmpty()) return;

            byte[] body = gzip(String.join("\n", batch).getBytes(StandardCharsets.UTF_8));
            String sig = hmac(body, config.tenantHmacKey);

            HttpURLConnection c = (HttpURLConnection) new URL(config.ingestUrl).openConnection();
            c.setConnectTimeout(10_000);
            c.setReadTimeout(10_000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-ndjson");
            c.setRequestProperty("Content-Encoding", "gzip");
            c.setRequestProperty("X-Tenant-Id", config.tenantId);
            c.setRequestProperty("X-Install-Id", sessions.installId());
            c.setRequestProperty("X-Signature", sig);
            // Advertise which key version signed this batch (additive; the
            // server also verifies by trying all live keys when absent).
            if (!config.tenantKeyId.isEmpty()) {
                c.setRequestProperty("X-Key-Id", config.tenantKeyId);
            }
            c.setRequestProperty("X-Sdk", "android/0.2.0");

            try (OutputStream os = c.getOutputStream()) { os.write(body); }

            int code = c.getResponseCode();
            if (code >= 200 && code < 300) {
                queue.ack(batch.size());
                backoffMs = 0;
                handleResponseCommands(c);
            } else if (code >= 400 && code < 500 && code != 429) {
                queue.ack(batch.size());   // poison batch: drop, never retry forever
                backoffMs = 0;
            } else {
                backoffMs = backoffMs == 0 ? 5_000 : backoffMs * 2;   // 5xx / 429
            }
            c.disconnect();
        } catch (Exception e) {
            backoffMs = backoffMs == 0 ? 5_000 : Math.min(backoffMs * 2, 60_000);
        }
    }

    /**
     * v0.2: the batch response may carry server-issued commands
     * ({"accepted": n, "commands": [{id, kind, sessionId}]}) — the action
     * channel's device leg (analyst kill switch). Parse defensively;
     * a malformed or absent body must never affect the upload loop.
     */
    private void handleResponseCommands(HttpURLConnection c) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (InputStream is = c.getInputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0 && bos.size() < 64_000) bos.write(buf, 0, n);
            }
            JSONObject resp = new JSONObject(bos.toString("UTF-8"));
            JSONArray commands = resp.optJSONArray("commands");
            if (commands != null && commands.length() > 0) {
                sessions.handleServerCommands(commands);
            }
        } catch (Throwable ignored) {}
    }

    private boolean isConnected() {
        try {
            ConnectivityManager cm =
                    (ConnectivityManager) app.getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm != null ? cm.getActiveNetworkInfo() : null;
            return ni != null && ni.isConnected();
        } catch (Exception e) {
            return true;   // fail open: attempt the upload
        }
    }

    private static byte[] gzip(byte[] in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) { gz.write(in); }
        return bos.toByteArray();
    }

    private static String hmac(byte[] body, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.encodeToString(mac.doFinal(body), Base64.NO_WRAP);
    }
}
