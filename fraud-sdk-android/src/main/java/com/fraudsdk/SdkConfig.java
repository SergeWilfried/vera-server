package com.fraudsdk;

/** Immutable SDK configuration. Build once in Application.onCreate(). */
public final class SdkConfig {
    public final String tenantId;
    public final Environment environment;
    public final String ingestUrl;
    public final byte[] tenantHmacKey;     // per-tenant signing key (provisioned at onboarding)
    public final String tenantKeyId;       // key version ("kid") of tenantHmacKey; "" if unversioned
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
        this.ingestUrl = b.ingestUrl != null ? b.ingestUrl : b.environment.defaultIngestUrl();
        this.tenantHmacKey = b.tenantHmacKey;
        this.tenantKeyId = b.tenantKeyId;
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
        private String ingestUrl;
        private byte[] tenantHmacKey;
        private String tenantKeyId = "";
        private String tenantHashSalt = "";
        private long idleTimeoutMs = 5 * 60 * 1000L;
        private int maxBatchSize = 50;
        private long uploadIntervalMs = 15 * 1000L;
        private boolean playIntegrityEnabled = true;
        private LocationTier locationTier = LocationTier.TIER1_OPPORTUNISTIC_COARSE;

        public Builder tenantId(String v) { this.tenantId = v; return this; }
        public Builder environment(Environment v) { this.environment = v; return this; }
        public Builder ingestUrl(String v) { this.ingestUrl = v; return this; }
        public Builder tenantHmacKey(byte[] v) { this.tenantHmacKey = v; return this; }
        public Builder tenantKeyId(String v) { this.tenantKeyId = v != null ? v : ""; return this; }
        public Builder tenantHashSalt(String v) { this.tenantHashSalt = v; return this; }
        public Builder idleTimeoutMs(long v) { this.idleTimeoutMs = v; return this; }
        public Builder maxBatchSize(int v) { this.maxBatchSize = v; return this; }
        public Builder uploadIntervalMs(long v) { this.uploadIntervalMs = v; return this; }
        public Builder playIntegrityEnabled(boolean v) { this.playIntegrityEnabled = v; return this; }
        public Builder locationTier(LocationTier v) { this.locationTier = v; return this; }

        public SdkConfig build() {
            if (tenantId == null || tenantId.isEmpty())
                throw new IllegalStateException("tenantId is required");
            if (tenantHmacKey == null || tenantHmacKey.length < 32)
                throw new IllegalStateException("tenantHmacKey (>=32 bytes) is required");
            return new SdkConfig(this);
        }
    }
}
