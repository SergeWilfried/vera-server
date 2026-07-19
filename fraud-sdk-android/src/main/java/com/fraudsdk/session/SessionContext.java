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

    /**
     * Signed token joining this session to your backend call.
     * Attach as e.g. X-Fraud-Session header; your backend forwards it
     * to the scoring API. Empty string if the SDK is disabled.
     */
    public String getSessionToken() {
        return mgr != null ? mgr.mintToken() : "";
    }
}
