package com.veratools.fraudsdk

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.provider.Settings
import android.view.Display
import android.view.WindowManager
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.function.Consumer

/**
 * Screen-share / remote-access detection for the Expo SDK, mirroring the native
 * Android SDK's RemoteAccessCollector. It detects the *effect* of remote control
 * / capture — there is no reliable "AnyDesk is installed" API — via:
 *
 *   - extra displays: a VirtualDisplay beyond the built-in screen, created by
 *     AnyDesk / TeamViewer / casting / MediaProjection screen-share. The
 *     all-versions workhorse tell.
 *   - screen recording (Android 15+): WindowManager.addScreenRecordingCallback,
 *     which fires for the on-device screen recorder too — the case an extra
 *     display alone misses. Requires the DETECT_SCREEN_RECORDING permission
 *     (declared in this module's manifest; install-time, no runtime prompt).
 *   - remote-control accessibility services: enabled services whose id matches a
 *     denylist of known remote-control packages.
 *
 * getStatus() is polled by collectors/remoteAccess.ts; the JS side raises the
 * local anti-scam banner and emits PASSIVE_REMOTE_ACCESS for server scoring.
 */
class VeraRemoteAccessModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  // Known remote-control / screen-share tools (accessibility-service id match).
  private val denylist = listOf(
    "anydesk", "teamviewer", "rustdesk", "airdroid", "aweray", "airmirror",
    "vnc", "splashtop"
  )

  @Volatile private var screenRecording = false
  private var callbackRegistered = false
  private var registeredWm: WindowManager? = null
  private val screenRecordingCallback = Consumer<Int> { state ->
    if (Build.VERSION.SDK_INT >= 35) {
      screenRecording = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
    }
  }

  override fun definition() = ModuleDefinition {
    Name("VeraRemoteAccess")

    AsyncFunction("getStatus") {
      ensureScreenRecordingCallback()

      val dm = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
      val extraDisplays = dm.displays.count { it.displayId != Display.DEFAULT_DISPLAY }
      val (suspect, matches) = enabledRemoteControlServices()

      mapOf(
        "screenShareLikely" to (extraDisplays > 0 || screenRecording),
        "screenRecording" to screenRecording,
        "extraDisplays" to extraDisplays,
        "accessibilitySuspect" to suspect,
        "accessibilityMatches" to matches
      )
    }

    OnDestroy { unregisterScreenRecordingCallback() }
  }

  // Register lazily (needs a visual/Activity context, which exists by the time
  // JS polls). Safe to call repeatedly; no-ops once registered or below API 35.
  @SuppressLint("NewApi")
  private fun ensureScreenRecordingCallback() {
    if (callbackRegistered || Build.VERSION.SDK_INT < 35) return
    val activity = appContext.currentActivity ?: return
    try {
      val wm = activity.windowManager
      val initial = wm.addScreenRecordingCallback(activity.mainExecutor, screenRecordingCallback)
      screenRecording = initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
      registeredWm = wm
      callbackRegistered = true
    } catch (e: Exception) {
      // Missing DETECT_SCREEN_RECORDING permission or OEM without support —
      // fall back to the display / accessibility checks only.
    }
  }

  @SuppressLint("NewApi")
  private fun unregisterScreenRecordingCallback() {
    if (!callbackRegistered || Build.VERSION.SDK_INT < 35) return
    try {
      registeredWm?.removeScreenRecordingCallback(screenRecordingCallback)
    } catch (e: Exception) {
      // ignore
    }
    registeredWm = null
    callbackRegistered = false
  }

  private fun enabledRemoteControlServices(): Pair<Boolean, List<String>> {
    val enabled = Settings.Secure.getString(
      context.contentResolver,
      Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
    ) ?: return false to emptyList()

    val matches = denylist.filter { enabled.contains(it, ignoreCase = true) }
    return (matches.isNotEmpty()) to matches
  }
}
