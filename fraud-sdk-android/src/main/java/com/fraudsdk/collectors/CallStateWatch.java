package com.fraudsdk.collectors;

import android.content.Context;
import android.media.AudioManager;

import com.fraudsdk.session.SessionManager;

import org.json.JSONObject;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Call-state transition watch — closes the window the per-event snapshot
 * leaves open. {@link CallSignalCollector} samples call state only at the
 * instant a business event fires, so the "hang up, then send it" coaching
 * pattern is invisible: the call ends seconds before TXN_INITIATED and the
 * snapshot shows no call. This watch polls AudioManager (each read <1ms)
 * and emits PASSIVE_CALL_STATE on every idle<->in-call transition, so the
 * backend can score "call ended moments before the transfer" (RECENT_CALL).
 *
 * The event envelope's ts is the transition time; the end event carries the
 * call's duration. Same VoIP coverage as the snapshot: MODE_IN_COMMUNICATION
 * catches WhatsApp/Telegram calls that telephony APIs never see.
 */
public final class CallStateWatch {

    private static final long POLL_MS = 5_000;

    private final Context appCtx;
    private final SessionManager sessions;
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "fraudsdk-callwatch");
                t.setDaemon(true);
                return t;
            });

    private boolean inCall = false;
    private String kind = "";
    private long startedAtMs = 0;

    public CallStateWatch(Context app, SessionManager sessions) {
        this.appCtx = app.getApplicationContext();
        this.sessions = sessions;
    }

    public void start() {
        scheduler.scheduleWithFixedDelay(this::pollOnce, POLL_MS, POLL_MS, TimeUnit.MILLISECONDS);
    }

    private void pollOnce() {
        try {
            AudioManager am = (AudioManager) appCtx.getSystemService(Context.AUDIO_SERVICE);
            if (am == null) return;

            int mode = am.getMode();
            boolean active = mode == AudioManager.MODE_IN_CALL
                    || mode == AudioManager.MODE_IN_COMMUNICATION;
            if (active == inCall) return;

            inCall = active;
            if (active) {
                kind = mode == AudioManager.MODE_IN_CALL ? "GSM" : "VoIP";
                startedAtMs = System.currentTimeMillis();
                sessions.enqueuePassive("CALL_STATE", new JSONObject()
                        .put("active", true)
                        .put("kind", kind));
            } else {
                sessions.enqueuePassive("CALL_STATE", new JSONObject()
                        .put("active", false)
                        .put("kind", kind)
                        .put("durationMs", System.currentTimeMillis() - startedAtMs));
            }
        } catch (Throwable ignored) {}
    }
}
