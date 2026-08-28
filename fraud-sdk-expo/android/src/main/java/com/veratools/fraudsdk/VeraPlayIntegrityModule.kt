package com.veratools.fraudsdk

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Play Integrity attestation for the RN SDK — the store-sanctioned verdict on
 * device genuineness, app authenticity and install licensing. The token is
 * opaque to the SDK: collectors/attestation.ts forwards it in a
 * PASSIVE_ATTESTATION event and the ingest server decodes it with Google.
 *
 * The nonce is computed by the JS side as SHA-256(sessionId|installId) so the
 * server can bind the verdict to this session's envelope and reject replays.
 *
 * Failure resolves (never rejects) with status set — an errored or absent
 * attestation is itself a scoring signal (ATTESTATION_MISSING), so it must
 * reach the wire rather than dying in a promise rejection.
 */
class VeraPlayIntegrityModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  override fun definition() = ModuleDefinition {
    Name("VeraPlayIntegrity")

    AsyncFunction("requestToken") { nonce: String, cloudProjectNumber: Double, promise: Promise ->
      try {
        val manager = IntegrityManagerFactory.create(context)
        manager.requestIntegrityToken(
          IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudProjectNumber(cloudProjectNumber.toLong())
            .build()
        )
          .addOnSuccessListener { resp ->
            promise.resolve(mapOf("status" to "OK", "token" to resp.token()))
          }
          .addOnFailureListener { e ->
            promise.resolve(mapOf("status" to "API_ERROR:${short(e)}", "token" to ""))
          }
      } catch (t: Throwable) {
        // Missing Play services, or the integrity library absent from the build
        promise.resolve(mapOf("status" to "UNAVAILABLE:${short(t)}", "token" to ""))
      }
    }
  }

  private fun short(t: Throwable): String {
    val msg = t.message ?: return t.javaClass.simpleName
    return "${t.javaClass.simpleName}:${msg.take(80)}"
  }
}
