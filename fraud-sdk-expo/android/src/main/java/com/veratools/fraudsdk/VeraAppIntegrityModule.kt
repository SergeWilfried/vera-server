package com.veratools.fraudsdk

import android.content.Context
import android.provider.Settings
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.BufferedReader
import java.io.FileReader

/**
 * The integrity fields JavaScript cannot reach — the parity gap between this
 * SDK's integrity collector (expo-device only) and the native Android SDK's
 * IntegrityCollector. Detection logic is a line-for-line port of that
 * collector, so both SDKs report the same evidence for the same handset:
 *
 *   - hookingFramework: frida / xposed / substrate mapped into our own
 *     process (/proc/self/maps). Feeds DEVICE_INTEGRITY (30) — a hooking
 *     framework is the instrumentation layer of overlay/banking trojans.
 *   - installerPackage: "" = manual install -> SIDELOADED_APP. The server
 *     treats an ABSENT field as unknown, so the JS side must only send this
 *     when the module is present — never fabricate it.
 *   - devOptionsEnabled: DEV_OPTIONS (10), weak but corroborating.
 *   - accessibilityServices: ALL enabled service packages (not just the
 *     remote-access denylist matches the VeraRemoteAccess module reports) —
 *     accessibility abuse is how banking trojans in the region operate.
 */
class VeraAppIntegrityModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private val hookLibs = listOf("frida", "xposed", "substrate")

  override fun definition() = ModuleDefinition {
    Name("VeraAppIntegrity")

    AsyncFunction("getStatus") {
      mapOf(
        "hookingFramework" to hookingFramework(),
        "installerPackage" to installerPackage(),
        "devOptionsEnabled" to devOptionsEnabled(),
        "accessibilityServices" to enabledAccessibilityServices()
      )
    }
  }

  private fun hookingFramework(): String {
    try {
      BufferedReader(FileReader("/proc/self/maps")).use { r ->
        var line = r.readLine()
        while (line != null) {
          val lower = line.lowercase()
          for (lib in hookLibs) if (lower.contains(lib)) return lib
          line = r.readLine()
        }
      }
    } catch (e: Exception) {
      // unreadable maps — absence of evidence, not evidence of integrity
    }
    return ""
  }

  @Suppress("DEPRECATION")
  private fun installerPackage(): String {
    return try {
      // "" = no installer recorded = manual install — itself the signal.
      context.packageManager.getInstallerPackageName(context.packageName) ?: ""
    } catch (e: Exception) {
      ""
    }
  }

  private fun devOptionsEnabled(): Boolean {
    return try {
      Settings.Global.getInt(
        context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
      ) != 0
    } catch (e: Exception) {
      false
    }
  }

  private fun enabledAccessibilityServices(): List<String> {
    return try {
      val setting = Settings.Secure.getString(
        context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
      ) ?: return emptyList()
      if (setting.isEmpty()) return emptyList()
      // package names only — the service class adds nothing but identifiers
      setting.split(":").map { s -> s.substringBefore('/') }.filter { it.isNotEmpty() }
    } catch (e: Exception) {
      emptyList()
    }
  }
}
