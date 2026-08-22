package com.veratools.fraudsdk

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Process
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Is this app instance a CLONE?
 *
 * The graph links multi-accounting on install_id (sessions joined on the same
 * install). A cloned container defeats that outright: Dual Apps / Secure Folder
 * run the clone as a separate Android user, and Parallel Space-style tools run
 * it in a userspace sandbox — either way the clone gets its own data dir, its
 * own keystore, and therefore its own installId. One handset then presents as
 * two unrelated devices, which is exactly the evasion this closes.
 *
 * Detects being cloned rather than the presence of a cloning tool. That is the
 * same choice VeraRemoteAccessModule makes (an extra VirtualDisplay, not "is
 * AnyDesk installed"), and it has the same payoff: no package denylist to
 * maintain, no <queries> declaration, nothing to sidestep by switching apps,
 * and no restricted permission anywhere near the host app's Play listing.
 */
class VeraContainerModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  override fun definition() = ModuleDefinition {
    Name("VeraContainer")

    AsyncFunction("getStatus") {
      val userId = androidUserId()
      val dir = dataDirCheck()

      mapOf(
        "androidUserId" to userId,
        "secondaryUser" to (userId > 0),
        "virtualized" to dir.virtualized,
        "dataDirBasis" to dir.basis,
        "adminPresent" to adminPresent()
      )
    }
  }

  private data class DirCheck(val virtualized: Boolean, val basis: String)

  /**
   * Android packs the user id into the uid: uid / PER_USER_RANGE. 0 is the
   * primary user; a dual-app clone or a work profile runs above it.
   */
  private fun androidUserId(): Int = try {
    Process.myUid() / 100000
  } catch (e: Exception) {
    0
  }

  /**
   * A userspace container rewrites the app's data dir to sit *inside* the host
   * container's own directory — e.g.
   *   /data/user/0/com.lbe.parallel.intl/parallel_intl/0/<our package>
   * instead of the expected
   *   /data/user/<n>/<our package>
   *
   * Only a nested path that still contains our own package counts. Anything
   * else is reported as unrecognised rather than as a clone: adopted storage
   * (/mnt/expand/<uuid>/…), device-encrypted dirs and OEM layouts all deviate
   * from the textbook shape on perfectly ordinary handsets, and a false clone
   * flag would land on real customers.
   */
  private fun dataDirCheck(): DirCheck {
    val pkg = context.packageName
    val raw = try {
      context.applicationInfo.dataDir ?: return DirCheck(false, "unavailable")
    } catch (e: Exception) {
      return DirCheck(false, "unavailable")
    }

    // Adopted storage is an ordinary configuration — normalise it away first.
    val path = raw.replace(Regex("^/mnt/expand/[0-9a-fA-F-]+"), "")
    val expected = Regex("^/data/(data|user/\\d+|user_de/\\d+)/" + Regex.escape(pkg) + "/?$")
    if (expected.matches(path)) return DirCheck(false, "standard")

    // Nested but still ours = running inside someone else's sandbox.
    if (path.contains("/$pkg")) return DirCheck(true, "nested")

    return DirCheck(false, "unrecognised")
  }

  /**
   * Whether any device admin is active. A work profile is also a secondary
   * user, and an MDM-managed handset is legitimate — this is what lets the
   * server tell "corporate profile" from "cloned app" instead of scoring every
   * enterprise device as an evasion.
   */
  private fun adminPresent(): Boolean = try {
    val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
    dpm?.activeAdmins?.isNotEmpty() == true
  } catch (e: Exception) {
    false
  }
}
