package com.fraudsdk;

/** Immutable SDK configuration. Build once in Application.onCreate().
 *
 *  v0.3: the SDK no longer holds the tenant HMAC key — uploads go to the
 *  collect path authenticated by the per-tenant NATIVE app key (X-App-Key),
 *  and the session token is minted server-side. The app key ships inside
 *  the APK (extractable by determined reverse engineering, unlike a web
 *  page it is not served to every visitor) and is rotatable per tenant;
 *  the forward path is device attestation presented in the same slot. */
public final class SdkConfig {
    public final String tenantId;
    public final Environment environment;
    /** Collector base URL (no path), e.g. https://collect.example.com */
    public final String collectorBaseUrl;
    /** Per-tenant native-app credential, sent as X-App-Key. */
    public final String appKey;
    public final String tenantHashSalt;    // per-tenant salt for Hashing.hash()
    public final long idleTimeoutMs;
    public final int maxBatchSize;
    public final long uploadIntervalMs;
    public final boolean playIntegrityEnabled;
    public final LocationTier locationTier;

    public enum LocationTier { TIER0_NONE, TIER1_OPPORTUNISTIC_COARSE, TIER2_OPT_IN_FINE }

    private SdkConfig(Builder b) {
        this.tenantId = b.tenantId;
        this.environment = b.environment;
        this.collectorBaseUrl = b.collectorBaseUrl != null
                ? b.collectorBaseUrl : b.environment.defaultBaseUrl();
        this.appKey = b.appKey;
        this.tenantHashSalt = b.tenantHashSalt;
        this.idleTimeoutMs = b.idleTimeoutMs;
        this.maxBatchSize = b.maxBatchSize;
        this.uploadIntervalMs = b.uploadIntervalMs;
        this.playIntegrityEnabled = b.playIntegrityEnabled;
        this.locationTier = b.locationTier;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String tenantId;
        private Environment environment = Environment.SANDBOX;
        private String collectorBaseUrl;
        private String appKey;
        private String tenantHashSalt = "";
        private long idleTimeoutMs = 5 * 60 * 1000L;
        private int maxBatchSize = 50;
        private long uploadIntervalMs = 15 * 1000L;
        private boolean playIntegrityEnabled = true;
        private LocationTier locationTier = LocationTier.TIER1_OPPORTUNISTIC_COARSE;

        public Builder tenantId(String v) { this.tenantId = v; return this; }
        public Builder environment(Environment v) { this.environment = v; return this; }
        public Builder collectorBaseUrl(String v) { this.collectorBaseUrl = v; return this; }
        public Builder appKey(String v) { this.appKey = v; return this; }
        public Builder tenantHashSalt(String v) { this.tenantHashSalt = v; return this; }
        public Builder idleTimeoutMs(long v) { this.idleTimeoutMs = v; return this; }
        public Builder maxBatchSize(int v) { this.maxBatchSize = v; return this; }
        public Builder uploadIntervalMs(long v) { this.uploadIntervalMs = v; return this; }
        public Builder playIntegrityEnabled(boolean v) { this.playIntegrityEnabled = v; return this; }
        public Builder locationTier(LocationTier v) { this.locationTier = v; return this; }

        public SdkConfig build() {
            if (tenantId == null || tenantId.isEmpty())
                throw new IllegalStateException("tenantId is required");
            if (appKey == null || appKey.isEmpty())
                throw new IllegalStateException("appKey is required (the per-tenant native app credential)");
            return new SdkConfig(this);
        }
    }
}
