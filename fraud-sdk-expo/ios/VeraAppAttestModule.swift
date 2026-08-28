import CryptoKit
import DeviceCheck
import ExpoModulesCore

/**
 * App Attest for iOS — Apple's hardware-backed attestation that this app
 * instance is the genuine, App Store-signed binary on a real device. The
 * Secure Enclave key is generated once per install and its id kept in
 * UserDefaults; the attestation object is opaque to the SDK and is forwarded
 * in a PASSIVE_ATTESTATION event for server-side verification against
 * Apple's certificate chain.
 *
 * The challenge (SHA-256(sessionId|installId), computed in JS) is hashed
 * again here as the clientDataHash, binding the attestation to this
 * session's envelope.
 *
 * Everything resolves (never rejects) with a status — unavailability (old
 * device, sideloaded build, simulator) is a scoring signal and must reach
 * the wire. DCAppAttestService is unsupported on simulators and most
 * TestFlight/dev-signed builds; the server treats UNAVAILABLE on those as
 * expected, and on App Store builds as ATTESTATION_MISSING.
 */
public class VeraAppAttestModule: Module {
  private static let keyIdPref = "vera_app_attest_key_id"

  public func definition() -> ModuleDefinition {
    Name("VeraAppAttest")

    AsyncFunction("attest") { (challenge: String, promise: Promise) in
      guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
        promise.resolve(["status": "UNAVAILABLE:unsupported", "keyId": "", "attestation": ""])
        return
      }
      let service = DCAppAttestService.shared
      let clientDataHash = Data(SHA256.hash(data: Data(challenge.utf8)))

      func doAttest(_ keyId: String) {
        service.attestKey(keyId, clientDataHash: clientDataHash) { blob, error in
          if let blob = blob {
            promise.resolve([
              "status": "OK",
              "keyId": keyId,
              "attestation": blob.base64EncodedString(),
            ])
          } else {
            // An invalidated key (app reinstall edge cases) must not wedge
            // attestation forever: drop it so the next session re-keys.
            UserDefaults.standard.removeObject(forKey: Self.keyIdPref)
            promise.resolve([
              "status": "API_ERROR:\(error.map { String(describing: $0).prefix(80) } ?? "attest")",
              "keyId": keyId, "attestation": "",
            ])
          }
        }
      }

      if let keyId = UserDefaults.standard.string(forKey: Self.keyIdPref) {
        doAttest(keyId)
      } else {
        service.generateKey { keyId, error in
          guard let keyId = keyId else {
            promise.resolve([
              "status": "API_ERROR:\(error.map { String(describing: $0).prefix(80) } ?? "generateKey")",
              "keyId": "", "attestation": "",
            ])
            return
          }
          UserDefaults.standard.set(keyId, forKey: Self.keyIdPref)
          doAttest(keyId)
        }
      }
    }
  }
}
