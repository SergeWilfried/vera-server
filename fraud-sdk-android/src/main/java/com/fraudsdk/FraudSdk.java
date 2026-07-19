package com.fraudsdk;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import android.widget.EditText;

import com.fraudsdk.capture.KeystrokeCapture;
import com.fraudsdk.capture.TouchCapture;
import com.fraudsdk.collectors.DeviceFingerprintCollector;
import com.fraudsdk.collectors.IntegrityCollector;
import com.fraudsdk.collectors.LocationCollector;
import com.fraudsdk.collectors.SimTelemetryCollector;
import com.fraudsdk.session.SessionContext;
import com.fraudsdk.session.SessionManager;
import com.fraudsdk.transport.EventQueue;
import com.fraudsdk.transport.EventUploader;

/**
 * Public entry point. All methods are fire-and-forget and never throw:
 * an SDK failure must never break the host app.
 *
 * <pre>
 *   FraudSdk.init(app, SdkConfig.builder()
 *       .tenantId("wallet-acme")
 *       .environment(Environment.PRODUCTION)
 *       .tenantHmacKey(key)
 *       .build());
 *   FraudSdk.session().setUser(FraudSdk.hash(msisdn));
 * </pre>
 */
public final class FraudSdk {
    static final String TAG = "FraudSdk";
    private static volatile FraudSdk instance;

    /**
     * Server-issued commands (the fraud platform's action channel).
     * Callbacks arrive on the main thread and must never be assumed to
     * fire — treat them as defense in depth, not the only logout path.
     */
    public interface CommandListener {
        /**
         * A fraud analyst terminated this session (kill switch). The SDK
         * has already rotated its own session and unbound the user; the
         * host app should force logout and invalidate its auth tokens.
         */
        void onSessionTerminated(String sessionId);
    }

    private final SdkConfig config;
    private final SessionManager sessionManager;
    private final EventQueue queue;
    private final EventUploader uploader;

    private FraudSdk(Context app, SdkConfig config) {
        this.config = config;
        Hashing.salt = config.tenantHashSalt;
        this.queue = new EventQueue(app);
        this.sessionManager = new SessionManager(app, config, queue);
        this.uploader = new EventUploader(app, config, queue, sessionManager);
    }

    /** Call once from Application.onCreate(). Idempotent. */
    public static void init(Application app, SdkConfig config) {
        try {
            if (instance != null) return;
            synchronized (FraudSdk.class) {
                if (instance != null) return;
                FraudSdk sdk = new FraudSdk(app, config);
                instance = sdk;

                // Passive capture wiring
                app.registerActivityLifecycleCallbacks(
                        new TouchCapture(sdk.sessionManager));

                // Passive collectors run off the main thread
                sdk.sessionManager.executor().execute(() -> {
                    sdk.sessionManager.enqueuePassive("DEVICE_FINGERPRINT",
                            new DeviceFingerprintCollector(app).collect());
                    sdk.sessionManager.enqueuePassive("SIM_TELEMETRY",
                            new SimTelemetryCollector(app).collect());
                    sdk.sessionManager.enqueuePassive("APP_INTEGRITY",
                            new IntegrityCollector(app, config).collect());
                    sdk.sessionManager.enqueuePassive("LOCATION_COARSE",
                            new LocationCollector(app, config).collect());
                });

                sdk.uploader.start();
            }
        } catch (Throwable t) {
            Log.w(TAG, "init failed, SDK disabled", t);
        }
    }

    /** The current session's public API. Safe no-op object if init failed. */
    public static SessionContext session() {
        FraudSdk sdk = instance;
        return sdk != null ? sdk.sessionManager.context() : SessionContext.NOOP;
    }

    /** Per-tenant salted SHA-256 for identifiers. */
    public static String hash(String value) { return Hashing.hash(value); }

    /**
     * Opt-in keystroke dynamics for one field — TIMING ONLY, never
     * characters or field content. Attach once per sensitive field with a
     * stable id, e.g. {@code FraudSdk.captureKeystrokes(pinField, "login.pin")}.
     * Timings are batched and sent when focus leaves the field. No-op if
     * the SDK failed to initialize.
     */
    public static void captureKeystrokes(EditText field, String fieldId) {
        FraudSdk sdk = instance;
        if (sdk != null && field != null && fieldId != null) {
            KeystrokeCapture.attach(sdk.sessionManager, field, fieldId);
        }
    }

    /** Force-upload queued events (e.g. right before a critical API call). */
    public static void flush() {
        FraudSdk sdk = instance;
        if (sdk != null) sdk.uploader.flushAsync();
    }

    /**
     * Register for server-issued commands (analyst kill switch). Call
     * after {@link #init}; commands arrive with at most one upload
     * interval of latency ({@code SdkConfig.uploadIntervalMs}).
     */
    public static void setCommandListener(CommandListener listener) {
        FraudSdk sdk = instance;
        if (sdk != null) sdk.sessionManager.setCommandListener(listener);
    }
}
