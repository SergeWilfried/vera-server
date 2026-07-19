package com.fraudsdk.capture;

import android.text.Editable;
import android.text.TextWatcher;
import android.widget.EditText;

import com.fraudsdk.session.SessionManager;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Opt-in keystroke-dynamics capture for a specific field.
 * Records TIMING ONLY — never characters, never field content:
 * inter-key latency, edit direction (insert/delete), burst length, paste events.
 *
 * Usage: KeystrokeCapture.attach(FraudSdk-internal sessions, editText, "login.pin");
 * A paste into a payee/PIN field is a classic coached-scam and bot signal.
 */
public final class KeystrokeCapture {

    private KeystrokeCapture() {}

    public static void attach(final SessionManager sessions,
                              final EditText field, final String fieldId) {
        try {
            field.addTextChangedListener(new TextWatcher() {
                private long lastKeyTs = 0;
                private final JSONArray timings = new JSONArray();
                private int prevLen = 0;

                @Override
                public void beforeTextChanged(CharSequence s, int st, int c, int a) {
                    prevLen = s != null ? s.length() : 0;
                }

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    try {
                        long now = System.currentTimeMillis();
                        int delta = (s != null ? s.length() : 0) - prevLen;
                        JSONObject k = new JSONObject();
                        k.put("dt", lastKeyTs > 0 ? now - lastKeyTs : -1);
                        k.put("op", delta >= 0 ? "i" : "d");
                        if (count > 2) k.put("paste", true);   // multi-char insert
                        lastKeyTs = now;
                        if (timings.length() < 200) timings.put(k);
                        sessions.touch();
                    } catch (Exception ignored) {}
                }

                @Override
                public void afterTextChanged(Editable s) {}

                // flush when focus leaves the field
                { field.setOnFocusChangeListener((v, hasFocus) -> {
                    if (!hasFocus && timings.length() > 0) {
                        final JSONArray batch = new JSONArray();
                        try {
                            for (int i = 0; i < timings.length(); i++) batch.put(timings.opt(i));
                            while (timings.length() > 0) timings.remove(0);
                        } catch (Exception ignored) {}
                        sessions.executor().execute(() -> {
                            try {
                                sessions.enqueuePassive("KEYSTROKES", new JSONObject()
                                        .put("fieldId", fieldId)
                                        .put("keys", batch));
                            } catch (Exception ignored) {}
                        });
                    }
                }); }
            });
        } catch (Throwable ignored) {}
    }
}
