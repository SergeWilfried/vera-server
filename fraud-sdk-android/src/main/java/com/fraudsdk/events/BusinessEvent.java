package com.fraudsdk.events;

import org.json.JSONObject;

/** Closed vocabulary of business events. Construct via factory methods only. */
public final class BusinessEvent {

    public enum Type {
        LOGIN_STARTED, LOGIN_RESULT,
        ONBOARDING_STARTED, ONBOARDING_COMPLETED,
        PAYEE_ADDED,
        TXN_INITIATED, TXN_CONFIRMED, TXN_SUBMITTED,
        STEP_UP_CHALLENGED, STEP_UP_RESULT,
        SUPPORT_CONTACTED, LOGOUT
    }

    public enum Outcome { SUCCESS, FAILURE, LOCKED, PASS, FAIL, ABANDONED }
    public enum Channel { P2P, BILL, MERCHANT, CASH_OUT, AIRTIME, BANK_TRANSFER }
    public enum PayeeChannel { WALLET, BANK, MERCHANT }
    public enum StepUpMethod { OTP_SMS, PIN, BIOMETRIC, USSD_PUSH }
    public enum SupportChannel { CALL, CHAT, EMAIL, AGENT }

    public final Type type;
    public final JSONObject payload;
    public final long tsMs;

    private BusinessEvent(Type type, JSONObject payload) {
        this.type = type;
        this.payload = payload != null ? payload : new JSONObject();
        this.tsMs = System.currentTimeMillis();
    }

    private static BusinessEvent of(Type t, JSONObject p) { return new BusinessEvent(t, p); }
    private static JSONObject obj() { return new JSONObject(); }
    private static JSONObject put(JSONObject o, String k, Object v) {
        try { o.put(k, v); } catch (Exception ignored) {}
        return o;
    }

    // ---- factories ----
    public static BusinessEvent loginStarted() { return of(Type.LOGIN_STARTED, null); }
    public static BusinessEvent loginResult(Outcome o) {
        return of(Type.LOGIN_RESULT, put(obj(), "outcome", o.name()));
    }
    public static BusinessEvent onboardingStarted() { return of(Type.ONBOARDING_STARTED, null); }
    public static BusinessEvent onboardingCompleted() { return of(Type.ONBOARDING_COMPLETED, null); }
    public static BusinessEvent payeeAdded(String hashedPayeeRef, PayeeChannel ch) {
        JSONObject p = put(obj(), "payeeRef", hashedPayeeRef);
        return of(Type.PAYEE_ADDED, put(p, "channel", ch.name()));
    }
    public static BusinessEvent txnInitiated(TransactionDraft d) {
        return of(Type.TXN_INITIATED, d.toJson());
    }
    public static BusinessEvent txnConfirmed() { return of(Type.TXN_CONFIRMED, null); }
    public static BusinessEvent txnSubmitted(String txnRef) {
        return of(Type.TXN_SUBMITTED, put(obj(), "txnRef", txnRef));
    }
    public static BusinessEvent stepUpChallenged(StepUpMethod m) {
        return of(Type.STEP_UP_CHALLENGED, put(obj(), "method", m.name()));
    }
    public static BusinessEvent stepUpResult(Outcome o) {
        return of(Type.STEP_UP_RESULT, put(obj(), "outcome", o.name()));
    }
    public static BusinessEvent supportContacted(SupportChannel ch) {
        return of(Type.SUPPORT_CONTACTED, put(obj(), "channel", ch.name()));
    }
    public static BusinessEvent logout() { return of(Type.LOGOUT, null); }
}
