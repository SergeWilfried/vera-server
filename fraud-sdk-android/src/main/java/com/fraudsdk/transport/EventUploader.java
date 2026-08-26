package com.fraudsdk.transport;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

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

/** Periodic batched upload: NDJSON -> gzip -> POST /v1/collect, authenticated
 *  by the per-tenant native app key (X-App-Key). v0.2 signed batches with the
 *  tenant HMAC key, which shipped the tenant secret inside every APK; the
 *  signing key now lives only server-side. Exponential backoff. */
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
    /** Epoch ms of the last POST (upload or heartbeat) — paces the poll. */
    private volatile long lastPostMs = 0;

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
        // disconnect() lives in finally — a request that throws mid-flight
        // must not leak its connection (see TokenClient for the same rule).
        HttpURLConnection c = null;
        try {
            if (backoffMs > 0) { Thread.sleep(Math.min(backoffMs, 60_000)); }
            if (!isConnected()) return;

            List<String> batch = queue.peek(config.maxBatchSize);
            if (batch.isEmpty()) {
                // Nothing to upload: poll for server commands so containment
                // does not depend on the customer interacting with the app.
                heartbeat();
                return;
            }

            byte[] body = gzip(String.join("\n", batch).getBytes(StandardCharsets.UTF_8));

            c = (HttpURLConnection)
                    new URL(config.collectorBaseUrl + "/v1/collect").openConnection();
            c.setConnectTimeout(10_000);
            c.setReadTimeout(10_000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-ndjson");
            c.setRequestProperty("Content-Encoding", "gzip");
            c.setRequestProperty("X-Tenant-Id", config.tenantId);
            c.setRequestProperty("X-App-Key", config.appKey);
            c.setRequestProperty("X-Install-Id", sessions.installId());
            c.setRequestProperty("X-Session-Id", sessions.currentSessionId());
            c.setRequestProperty("X-Sdk", "android/0.3.0");

            try (OutputStream os = c.getOutputStream()) { os.write(body); }
            lastPostMs = System.currentTimeMillis();

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
        } catch (Exception e) {
            backoffMs = backoffMs == 0 ? 5_000 : Math.min(backoffMs * 2, 60_000);
        } finally {
            if (c != null) c.disconnect();
        }
    }

    /**
     * Empty POST that exists only to collect pending server commands. The
     * session id travels in X-Session-Id, since there are no events to carry
     * it — an idle app must still be reachable by the analyst kill switch.
     */
    private void heartbeat() {
        long every = config.heartbeatMs;
        if (every <= 0 || System.currentTimeMillis() - lastPostMs < every) return;
        lastPostMs = System.currentTimeMillis();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection)
                    new URL(config.collectorBaseUrl + "/v1/collect").openConnection();
            c.setConnectTimeout(10_000);
            c.setReadTimeout(10_000);
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-ndjson");
            c.setRequestProperty("X-Tenant-Id", config.tenantId);
            c.setRequestProperty("X-App-Key", config.appKey);
            c.setRequestProperty("X-Install-Id", sessions.installId());
            c.setRequestProperty("X-Session-Id", sessions.currentSessionId());
            c.setRequestProperty("X-Sdk", "android/0.3.0");
            try (OutputStream os = c.getOutputStream()) { os.write(new byte[0]); }
            if (c.getResponseCode() / 100 == 2) handleResponseCommands(c);
        } catch (Exception ignored) {
            /* offline — the next beat retries */
        } finally {
            if (c != null) c.disconnect();
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
}
