package com.fraudsdk.session;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import com.fraudsdk.FraudSdk;
import com.fraudsdk.SdkConfig;
import com.fraudsdk.collectors.CallSignalCollector;
import com.fraudsdk.events.BusinessEvent;
import com.fraudsdk.transport.EventQueue;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Owns session lifecycle: id rotation, idle timeout, user binding, event envelopes. */
public final class SessionManager {

    private static final String PREFS = "fraudsdk";
    private static final String KEY_INSTALL_ID = "install_id";

    private final Context appCtx;
    private final SdkConfig config;
    private final EventQueue queue;
    private final SessionContext context;
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "fraudsdk-worker");
                t.setDaemon(true);
                return t;
            });

    private final String installId;
    private final AtomicReference<String> sessionId = new AtomicReference<>();
    private final AtomicReference<String> userRef = new AtomicReference<>();
    private final AtomicLong lastActivityMs = new AtomicLong(System.currentTimeMillis());
    private final AtomicReference<FraudSdk.CommandListener> commandListener =
            new AtomicReference<>();

    public SessionManager(Context app, SdkConfig config, EventQueue queue) {
        this.appCtx = app.getApplicationContext();
        this.config = config;
        this.queue = queue;
        this.context = new SessionContext(this);
        this.installId = loadOrCreateInstallId(app);
        rotateSession();
    }

    public SessionContext context() { return context; }
    public ExecutorService executor() { return executor; }
    public String installId() { return installId; }
    public String currentSessionId() { return sessionId.get(); }

    // ---- lifecycle ----

    private static String loadOrCreateInstallId(Context app) {
        SharedPreferences sp = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String id = sp.getString(KEY_INSTALL_ID, null);
        if (id == null) {
            id = uuidV7();
            sp.edit().putString(KEY_INSTALL_ID, id).apply();
        }
        return id;
    }

    private void rotateSession() {
        sessionId.set(uuidV7());
        lastActivityMs.set(System.currentTimeMillis());
    }

    /** Called by capture layer on any user interaction. */
    public void touch() {
        long now = System.currentTimeMillis();
        long last = lastActivityMs.getAndSet(now);
        if (now - last > config.idleTimeoutMs) {
            rotateSession();          // idle timeout => new session
        }
    }

    void setUser(String ref) { userRef.set(ref); }

    void clearUser() {
        userRef.set(null);
        rotateSession();
    }

    String mintToken() {
        return SessionToken.mint(config.tenantId, sessionId.get(),
                installId, userRef.get(), config.tenantHmacKey);
    }

    // ---- server commands (action channel, device leg) ----

    public void setCommandListener(FraudSdk.CommandListener l) {
        commandListener.set(l);
    }

    /**
     * Called from the uploader thread with the /v1/events batch-response
     * commands. TERMINATE_SESSION: ack inside the dying session, unbind
     * the user, rotate the session id (which invalidates future tokens
     * for the killed session), then notify the host app on the main
     * thread so it can force logout / invalidate its own auth tokens.
     * Commands targeting a session other than the current one are stale
     * (the session already rotated) and are ignored.
     */
    public void handleServerCommands(JSONArray commands) {
        try {
            for (int i = 0; i < commands.length(); i++) {
                JSONObject cmd = commands.optJSONObject(i);
                if (cmd == null) continue;
                if (!"TERMINATE_SESSION".equals(cmd.optString("kind"))) continue;

                final String current = sessionId.get();
                String target = cmd.optString("sessionId", "");
                if (!target.isEmpty() && !target.equals(current)) continue;   // stale

                enqueuePassive("COMMAND_ACK", new JSONObject()
                        .put("commandId", cmd.optString("id"))
                        .put("kind", "TERMINATE_SESSION"));
                userRef.set(null);
                rotateSession();

                final FraudSdk.CommandListener l = commandListener.get();
                if (l != null) {
                    new Handler(Looper.getMainLooper()).post(() -> {
                        try { l.onSessionTerminated(current); } catch (Throwable ignored) {}
                    });
                }
            }
        } catch (Throwable ignored) {}
    }

    // ---- enqueue ----

    void enqueueBusiness(BusinessEvent e) {
        touch();
        executor.execute(() -> {
            try {
                JSONObject o = envelope("BIZ_" + e.type.name());
                o.put("payload", e.payload);
                o.put("ts", e.tsMs);
                // in-call context at the moment of the event (coached-scam signal)
                o.put("callSignals", CallSignalCollector.snapshot(appCtx));
                queue.offer(o);
            } catch (Exception ignored) {}
        });
    }

    void screenViewed(String screenId) {
        touch();
        executor.execute(() -> {
            try {
                JSONObject o = envelope("SCREEN_VIEWED");
                o.put("payload", new JSONObject().put("screenId", screenId));
                queue.offer(o);
            } catch (Exception ignored) {}
        });
    }

    /** Used by collectors and the capture layer. Never call from the main thread. */
    public void enqueuePassive(String type, JSONObject payload) {
        try {
            JSONObject o = envelope("PASSIVE_" + type);
            o.put("payload", payload != null ? payload : new JSONObject());
            queue.offer(o);
        } catch (Exception ignored) {}
    }

    private JSONObject envelope(String type) throws Exception {
        JSONObject o = new JSONObject();
        o.put("type", type);
        o.put("sessionId", sessionId.get());
        o.put("installId", installId);
        String u = userRef.get();
        if (u != null) o.put("userRef", u);
        o.put("ts", System.currentTimeMillis());
        return o;
    }

    /** UUIDv7-ish: 48-bit unix ms + random. Time-sortable server-side. */
    private static String uuidV7() {
        long ms = System.currentTimeMillis();
        SecureRandom r = new SecureRandom();
        long hi = (ms << 16) | (0x7000 | (r.nextInt() & 0x0FFF));
        long lo = (r.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(hi, lo).toString();
    }
}
