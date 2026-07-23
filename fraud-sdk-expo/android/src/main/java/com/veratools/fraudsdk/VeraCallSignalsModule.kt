package com.veratools.fraudsdk

import android.content.Context
import android.media.AudioDeviceInfo
import android.media.AudioManager
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Permissionless in-call detection for the Expo SDK, mirroring the native
 * Android SDK's CallSignalCollector — the coached-scam signal:
 *
 *   MODE_IN_CALL          -> active GSM/VoLTE call
 *   MODE_IN_COMMUNICATION -> active VoIP call (WhatsApp/Telegram/Messenger)
 *   speakerphone/headset  -> victim free to follow instructions in-app
 *
 * VoIP coverage is the critical part: scam coaching in the region happens
 * overwhelmingly over WhatsApp calls, invisible to telephony APIs. Each read
 * is <1ms; collectors/callSignals.ts polls it, attaches the latest snapshot
 * to business events (ACTIVE_CALL scoring) and reports idle<->in-call
 * transitions (RECENT_CALL scoring).
 */
class VeraCallSignalsModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  override fun definition() = ModuleDefinition {
    Name("VeraCallSignals")

    AsyncFunction("getStatus") {
      val am = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
      val mode = am.mode

      var bt = false
      var wired = false
      for (d in am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
        when (d.type) {
          AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
          AudioDeviceInfo.TYPE_BLUETOOTH_A2DP -> bt = true
          AudioDeviceInfo.TYPE_WIRED_HEADSET,
          AudioDeviceInfo.TYPE_WIRED_HEADPHONES -> wired = true
        }
      }

      mapOf(
        "inGsmCall" to (mode == AudioManager.MODE_IN_CALL),
        "inVoipCall" to (mode == AudioManager.MODE_IN_COMMUNICATION),
        "ringing" to (mode == AudioManager.MODE_RINGTONE),
        "speakerOn" to am.isSpeakerphoneOn,
        "btAudio" to bt,
        "wiredHeadset" to wired
      )
    }
  }
}
