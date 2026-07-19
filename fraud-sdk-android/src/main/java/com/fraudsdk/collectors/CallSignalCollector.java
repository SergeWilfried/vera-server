package com.fraudsdk.collectors;

import android.content.Context;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.os.Build;

import org.json.JSONObject;

/**
 * Permissionless in-call detection via AudioManager — the coached-scam signal.
 *
 *  MODE_IN_CALL          -> active GSM/VoLTE call
 *  MODE_IN_COMMUNICATION -> active VoIP call (WhatsApp/Telegram/Messenger voice)
 *  speakerphoneOn        -> victim likely following instructions while in-app
 *
 * VoIP coverage is the critical part: scam coaching in the region happens
 * overwhelmingly over WhatsApp calls, invisible to telephony APIs.
 * Snapshot is cheap (<1ms); taken at every business event so the scoring
 * backend sees e.g. "TXN_INITIATED during VoIP call on speaker" as one fact.
 */
public final class CallSignalCollector {

    private CallSignalCollector() {}

    public static JSONObject snapshot(Context app) {
        JSONObject o = new JSONObject();
        try {
            AudioManager am = (AudioManager) app.getSystemService(Context.AUDIO_SERVICE);
            if (am == null) return o;

            int mode = am.getMode();
            o.put("audioMode", mode);
            o.put("inGsmCall", mode == AudioManager.MODE_IN_CALL);
            o.put("inVoipCall", mode == AudioManager.MODE_IN_COMMUNICATION);
            o.put("ringing", mode == AudioManager.MODE_RINGTONE);
            o.put("speakerOn", am.isSpeakerphoneOn());
            o.put("musicActive", am.isMusicActive());

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                boolean bt = false, wired = false;
                for (AudioDeviceInfo d : am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
                    int t = d.getType();
                    if (t == AudioDeviceInfo.TYPE_BLUETOOTH_SCO
                            || t == AudioDeviceInfo.TYPE_BLUETOOTH_A2DP) bt = true;
                    if (t == AudioDeviceInfo.TYPE_WIRED_HEADSET
                            || t == AudioDeviceInfo.TYPE_WIRED_HEADPHONES) wired = true;
                }
                o.put("btAudio", bt);
                o.put("wiredHeadset", wired);
            }
        } catch (Exception ignored) {}
        return o;
    }
}
