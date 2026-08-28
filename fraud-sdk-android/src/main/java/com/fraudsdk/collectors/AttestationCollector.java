package com.fraudsdk.collectors;

import android.content.Context;

import com.fraudsdk.SdkConfig;
import com.fraudsdk.session.SessionManager;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Play Integrity attestation — the store-sanctioned replacement for half the
 * heuristics in IntegrityCollector. The device asks Play for a signed verdict
 * (genuine device / genuine app / licensed install); the SDK never inspects
 * the token, it forwards it opaquely as PASSIVE_ATTESTATION and the ingest
 * server decodes it with Google (decodeIntegrityToken) using the tenant's
 * service-account credentials.
 *
 * Replay binding: the request nonce is SHA-256(sessionId|installId),
 * URL-safe base64. The server recomputes it from the event envelope and
 * refuses a verdict whose embedded nonce does not match — a token captured
 * from one device/session cannot vouch for another. (Server-issued
 * challenges are the follow-up hardening step.)
 *
 * Failure is a signal, not an error: if Play services are absent, the API
 * errors, or the client library was not compiled in (it is compileOnly —
 * the tenant build must include com.google.android.play:integrity), a
 * PASSIVE_ATTESTATION event with status UNAVAILABLE/API_ERROR is emitted so
 * the server can score ATTESTATION_MISSING instead of assuming the best.
 */
public final class AttestationCollector {

    private AttestationCollector() {}

    /** Fire the async attestation request; events are enqueued when it lands. */
    public static void request(Context app, SdkConfig config, SessionManager sm) {
        if (config.cloudProjectNumber <= 0) {
            return;      // tenant has not enabled Play Integrity
        }
        final String nonce = nonce(sm.currentSessionId(), sm.installId());
        try {
            IntegrityManager manager = IntegrityManagerFactory.create(app);
            manager.requestIntegrityToken(
                            IntegrityTokenRequest.builder()
                                    .setNonce(nonce)
                                    .setCloudProjectNumber(config.cloudProjectNumber)
                                    .build())
                    .addOnSuccessListener((IntegrityTokenResponse resp) ->
                            emit(sm, "OK", resp.token(), nonce))
                    .addOnFailureListener(e ->
                            emit(sm, "API_ERROR:" + shortError(e), "", nonce));
        } catch (Throwable t) {
            // NoClassDefFoundError when the integrity library is not in the
            // tenant build, or Play services are missing entirely.
            emit(sm, "UNAVAILABLE:" + shortError(t), "", nonce);
        }
    }

    private static void emit(SessionManager sm, String status, String token, String nonce) {
        sm.executor().execute(() -> {
            try {
                sm.enqueuePassive("ATTESTATION", new JSONObject()
                        .put("provider", "PLAY_INTEGRITY")
                        .put("status", status)
                        .put("token", token)
                        .put("nonce", nonce));
            } catch (Exception ignored) {}
        });
    }

    /** SHA-256(sessionId|installId) as URL-safe base64 without padding. */
    static String nonce(String sessionId, String installId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((sessionId + "|" + installId)
                    .getBytes(StandardCharsets.UTF_8));
            return android.util.Base64.encodeToString(d,
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP
                            | android.util.Base64.NO_PADDING);
        } catch (Exception e) {
            return "";
        }
    }

    private static String shortError(Throwable t) {
        String name = t.getClass().getSimpleName();
        String msg = t.getMessage();
        if (msg == null) return name;
        return name + ":" + (msg.length() > 80 ? msg.substring(0, 80) : msg);
    }
}
