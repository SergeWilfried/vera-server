import AVFoundation
import CallKit
import ExpoModulesCore

/**
 * In-call detection for iOS — the coached-scam signal the RN SDK could not
 * see before. CXCallObserver reports both carrier calls and CallKit-integrated
 * VoIP calls (WhatsApp, Telegram, Messenger all integrate CallKit on iOS), so
 * VoIP coaching coverage is native here — unlike Android telephony APIs.
 *
 * iOS gives a third-party app no way to tell a carrier call from another
 * app's CallKit call, so the generic in-call flag is reported as inGsmCall
 * and inVoipCall stays false — the wire shape stays identical to Android.
 *
 * Audio route: builtInReceiver (phone at the ear) means the victim cannot be
 * typing a transfer; speaker/bluetooth/wired means they are free to follow
 * the caller's instructions inside the app (CALL_HANDS_FREE scoring).
 */
public class VeraCallSignalsModule: Module {
  private let callObserver = CXCallObserver()

  public func definition() -> ModuleDefinition {
    Name("VeraCallSignals")

    AsyncFunction("getStatus") { () -> [String: Any] in
      let calls = self.callObserver.calls.filter { !$0.hasEnded }
      let inCall = calls.contains { $0.hasConnected }
      let ringing = calls.contains { !$0.hasConnected && !$0.isOutgoing }

      var speaker = false
      var bt = false
      var wired = false
      for output in AVAudioSession.sharedInstance().currentRoute.outputs {
        switch output.portType {
        case .builtInSpeaker:
          speaker = true
        case .bluetoothHFP, .bluetoothA2DP, .bluetoothLE:
          bt = true
        case .headphones, .headsetMic:
          wired = true
        default:
          break
        }
      }

      return [
        "inGsmCall": inCall,
        "inVoipCall": false,
        "ringing": ringing,
        "speakerOn": speaker,
        "btAudio": bt,
        "wiredHeadset": wired,
      ]
    }
  }
}
