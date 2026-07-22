package com.veratools.fraudsdk

import android.content.Context
import android.hardware.display.DisplayManager
import android.provider.Settings
import android.view.Display
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Screen-share / remote-access detection for the Expo SDK, mirroring the native
 * Android SDK's RemoteAccessCollector. It detects the *effect* of remote control
 * — there is no reliable "AnyDesk is installed" API — via:
 *
 *   - extra displays: a VirtualDisplay beyond the built-in screen is what
 *     AnyDesk / TeamViewer / MediaProjection screen-share create. The
 *     all-versions workhorse tell.
 *   - remote-control accessibility services: enabled services whose id matches a
 *     denylist of known remote-control packages.
 *
 * getStatus() is polled by collectors/remoteAccess.ts; the JS side raises the
 * local anti-scam banner and emits PASSIVE_REMOTE_ACCESS for server scoring.
 * No runtime permission is required for either check.
 */
class VeraRemoteAccessModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  // Known remote-control / screen-share tools (accessibility-service id match).
  private val denylist = listOf(
    "anydesk", "teamviewer", "rustdesk", "airdroid", "aweray", "airmirror",
    "vnc", "splashtop", "airirol"
  )

  override fun definition() = ModuleDefinition {
    Name("VeraRemoteAccess")

    AsyncFunction("getStatus") {
      val dm = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
      val extraDisplays = dm.displays.count { it.displayId != Display.DEFAULT_DISPLAY }
      val (suspect, matches) = enabledRemoteControlServices()

      mapOf(
        "screenShareLikely" to (extraDisplays > 0),
        "extraDisplays" to extraDisplays,
        "accessibilitySuspect" to suspect,
        "accessibilityMatches" to matches
      )
    }
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
