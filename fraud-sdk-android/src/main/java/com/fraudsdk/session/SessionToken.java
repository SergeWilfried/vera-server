package com.fraudsdk.session;

import android.util.Base64;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Compact signed token: base64url(header.payload).base64url(hmac). ~200 bytes. */
final class SessionToken {
    private SessionToken() {}

    static String mint(String tenantId, String sessionId, String installId,
                       String userRef, byte[] hmacKey) {
        try {
            JSONObject p = new JSONObject();
            p.put("t", tenantId);
            p.put("s", sessionId);
            p.put("d", installId);
            if (userRef != null) p.put("u", userRef);
            p.put("iat", System.currentTimeMillis() / 1000);
            byte[] body = p.toString().getBytes("UTF-8");
            String b64 = Base64.encodeToString(body,
                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            String sig = Base64.encodeToString(mac.doFinal(b64.getBytes("UTF-8")),
                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            return b64 + "." + sig;
        } catch (Exception e) {
            return "";
        }
    }
}
