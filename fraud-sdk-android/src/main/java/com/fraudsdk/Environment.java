package com.fraudsdk;

public enum Environment {
    SANDBOX("https://collect.sandbox.example.com"),
    PRODUCTION("https://collect.example.com");

    private final String baseUrl;
    Environment(String baseUrl) { this.baseUrl = baseUrl; }
    String defaultBaseUrl() { return baseUrl; }
}
