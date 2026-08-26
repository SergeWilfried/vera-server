package com.fraudsdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** SHA-256 with per-tenant salt. Use for MSISDNs, account numbers, payee refs.
 *  Contract shared byte-for-byte with the Expo and web SDKs:
 *  sha256(salt_utf8 || trim(value)_utf8), lowercase hex.
 *
 *  Cross-SDK test vectors — all SDKs must produce exactly these:
 *    ("", "olivia@demobank.cz")
 *      -> 0dbb84a570fa61f59f29885c5fcd314d43110e91af23f6d7de73416913df1ce1
 *    ("pepper-tenant-1", "  +225 07 88 00 12  ")   (trims to the bare number)
 *      -> e13016792da46cfd00eda399cb03eef77ce4f18a8c4bd913b3428b0387022ffc
 *    ("pepper-tenant-1", "c\u00f4te@exemple.ci")       (UTF-8, not a Latin-1 slip)
 *      -> 2db329d52aa30cbd2933e94bd12d72c6f183bfb54f933a98195616ec5c9e6837 */
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
