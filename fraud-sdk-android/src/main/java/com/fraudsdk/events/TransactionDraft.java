package com.fraudsdk.events;

import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/** PII-light transaction context. Exact amounts stay server-side; use buckets. */
public final class TransactionDraft {

    public enum AmountBucket { MICRO, LOW, MID, HIGH, VERY_HIGH }

    public final AmountBucket amountBucket;
    public final String currency;
    public final String payeeRef;     // hashed
    public final boolean payeeIsNew;
    public final BusinessEvent.Channel channel;
    public final Map<String, String> tags;

    private TransactionDraft(Builder b) {
        this.amountBucket = b.amountBucket;
        this.currency = b.currency;
        this.payeeRef = b.payeeRef;
        this.payeeIsNew = b.payeeIsNew;
        this.channel = b.channel;
        this.tags = b.tags;
    }

    JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("amountBucket", amountBucket != null ? amountBucket.name() : null);
            o.put("currency", currency);
            o.put("payeeRef", payeeRef);
            o.put("payeeIsNew", payeeIsNew);
            o.put("channel", channel != null ? channel.name() : null);
            if (!tags.isEmpty()) o.put("tags", new JSONObject(tags));
        } catch (Exception ignored) {}
        return o;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private AmountBucket amountBucket;
        private String currency = "XOF";
        private String payeeRef;
        private boolean payeeIsNew;
        private BusinessEvent.Channel channel;
        private final Map<String, String> tags = new LinkedHashMap<>();

        public Builder amountBucket(AmountBucket v) { this.amountBucket = v; return this; }
        public Builder currency(String v) { this.currency = v; return this; }
        public Builder payeeRef(String hashed) { this.payeeRef = hashed; return this; }
        public Builder payeeIsNew(boolean v) { this.payeeIsNew = v; return this; }
        public Builder channel(BusinessEvent.Channel v) { this.channel = v; return this; }
        public Builder tag(String k, String v) {
            if (tags.size() < 10) tags.put(k, v);
            return this;
        }
        public TransactionDraft build() { return new TransactionDraft(this); }
    }
}
