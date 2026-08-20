package com.fraudsdk.session;

import com.fraudsdk.events.BusinessEvent;

/**
 * Public per-session API. Obtain via FraudSdk.session().
 * All methods are fire-and-forget and never throw.
 */
public class SessionContext {

    /** Returned when the SDK failed to initialize: every call is a silent no-op. */
    public static final SessionContext NOOP = new SessionContext(null);

    private final SessionManager mgr;

    SessionContext(SessionManager mgr) { this.mgr = mgr; }

    /** Bind a pseudonymous user reference (use FraudSdk.hash()) after login. */
    public void setUser(String userRef) {
        if (mgr != null) mgr.setUser(userRef);
    }

    /** Unbind on logout. Also rotates the session. */
    public void clearUser() {
        if (mgr != null) mgr.clearUser();
    }

    /** Record a business event. */
    public void event(BusinessEvent e) {
        if (mgr != null && e != null) mgr.enqueueBusiness(e);
    }

    /** Record navigation context. Use stable screen ids, not titles. */
    public void screenViewed(String screenId) {
        if (mgr != null && screenId != null) mgr.screenViewed(screenId);
    }

    /** Receives a session token ("" if the SDK is disabled or the
     *  collector is unreachable). Always called on the main thread. */
    public interface TokenCallback {
        void onToken(String token);
    }

    /**
     * Session token joining this session to your backend call (attach as
     * e.g. X-Fraud-Session; your backend forwards it to /v1/score). Tokens
     * are minted SERVER-SIDE — the app holds no signing key — so this
     * returns the cached token, which may briefly be "" right after init,
     * login or a session rotation while the mint is in flight. Prefer
     * {@link #getSessionToken(TokenCallback)} right before a payment.
     */
    public String getSessionToken() {
        return mgr != null ? mgr.currentToken() : "";
    }

    /** Ensure a fresh server-minted token, delivered on the main thread. */
    public void getSessionToken(TokenCallback cb) {
        if (mgr != null) mgr.tokenAsync(cb);
        else cb.onToken("");
    }
}
