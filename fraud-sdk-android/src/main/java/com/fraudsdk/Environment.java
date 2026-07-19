package com.fraudsdk;

public enum Environment {
    SANDBOX("https://ingest.sandbox.example.com/v1/events"),
    PRODUCTION("https://ingest.example.com/v1/events");

    private final String url;
    Environment(String url) { this.url = url; }
    String defaultIngestUrl() { return url; }
}
