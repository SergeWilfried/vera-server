package com.fraudsdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** SHA-256 with per-tenant salt. Use for MSISDNs, account numbers, payee refs. */
public final class Hashing {
    private Hashing() {}

    static String salt = "";

    /** Returns lowercase hex SHA-256(salt || value). Never throws; returns "" on failure. */
    public static String hash(String value) {
        if (value == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] d = md.digest(value.trim().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
