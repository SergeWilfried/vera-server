package com.fraudsdk.session;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import com.fraudsdk.FraudSdk;
import com.fraudsdk.SdkConfig;
import com.fraudsdk.collectors.CallSignalCollector;
import com.fraudsdk.collectors.RemoteAccessCollector;
import com.fraudsdk.events.BusinessEvent;
import com.fraudsdk.transport.EventQueue;
import com.fraudsdk.transport.TokenClient;

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

    // Server-minted session token cache (the app holds no signing key).
    // A cached token is served only while it is fresh (< TOKEN_TTL_MS) AND
    // still matches the current (sessionId, userRef) — rotation or a user
    // change invalidates it and triggers a background re-mint.
    private static final long TOKEN_TTL_MS = 45 * 60 * 1000L;
    private volatile String cachedToken = "";
    private volatile String tokenSessionId = "";
    private volatile String tokenUserRef = null;
    private volatile long tokenMintedAt = 0L;

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

    void setUser(String ref) {
        userRef.set(ref);
        refreshTokenAsync();
    }

    void clearUser() {
        userRef.set(null);
        rotateSession();
        refreshTokenAsync();
    }

    private boolean tokenUsable() {
        String tok = cachedToken;
        if (tok.isEmpty()) return false;
        if (!sessionId.get().equals(tokenSessionId)) return false;
        String u = userRef.get();
        String tu = tokenUserRef;
        if (u == null ? tu != null : !u.equals(tu)) return false;
        return System.currentTimeMillis() - tokenMintedAt < TOKEN_TTL_MS;
    }

    /** Mint (on the worker thread) a token for the CURRENT identity; the
     *  result is cached only if the session has not rotated meanwhile. */
    public void refreshTokenAsync() {
        final String sid = sessionId.get();
        final String u = userRef.get();
        executor.execute(() -> {
            String tok = TokenClient.mint(config, sid, installId, u);
            if (tok != null && sid.equals(sessionId.get())) {
                cachedToken = tok;
                tokenSessionId = sid;
                tokenUserRef = u;
                tokenMintedAt = System.currentTimeMillis();
            }
        });
    }

    /** Cached token for the current identity, or "" when none is fresh yet
     *  (a background re-mint is kicked off in that case). */
    String currentToken() {
        if (tokenUsable()) return cachedToken;
        refreshTokenAsync();
        return "";
    }

    /** Ensure a fresh token, then deliver it on the main thread ("" on
     *  failure — e.g. collector unreachable). */
    void tokenAsync(final SessionContext.TokenCallback cb) {
        if (tokenUsable()) {
            final String tok = cachedToken;
            new Handler(Looper.getMainLooper()).post(() -> cb.onToken(tok));
            return;
        }
        final String sid = sessionId.get();
        final String u = userRef.get();
        executor.execute(() -> {
            String tok = TokenClient.mint(config, sid, installId, u);
            if (tok != null && sid.equals(sessionId.get())) {
                cachedToken = tok;
                tokenSessionId = sid;
                tokenUserRef = u;
                tokenMintedAt = System.currentTimeMillis();
            }
            final String out = tok != null ? tok : "";
            new Handler(Looper.getMainLooper()).post(() -> cb.onToken(out));
        });
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
                cachedToken = "";
                refreshTokenAsync();

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
                // remote-access context at the moment of the event (ODF signal);
                // screen-share usually starts right before the transfer
                JSONObject ra = RemoteAccessCollector.snapshot(appCtx);
                o.put("remoteAccess", ra);
                queue.offer(o);
                // surface it as its own passive event too when it flips suspect
                if (RemoteAccessCollector.isSuspect(ra)) {
                    enqueuePassive("REMOTE_ACCESS", RemoteAccessCollector.snapshot(appCtx));
                }
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
        // Client-generated id makes uploads dedupable server-side (the SDK
        // fleet can't be retrofitted later; enforcement can be).
        o.put("eventId", uuidV7());
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
