package com.veratools.fraudsdk

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.net.NetworkInterface
import java.security.KeyStore

/**
 * Transport-integrity checks: is this session's traffic being tunnelled, and is
 * anything positioned to read it? These are the two RASP-style checks the
 * scoring engine had no input for (VPN/proxy and MITM).
 *
 * Read once per session by collectors/netIntegrity.ts and scored server-side as
 * VPN_ACTIVE / PROXY_CONFIGURED / MITM_CA_INSTALLED. Nothing here blocks: a VPN
 * is ordinary consumer behaviour and privacy tooling is not fraud. These earn
 * their weight in combination — a tunnel plus a fresh install plus an active
 * call is a very different session from a tunnel on its own.
 *
 * All three read local system state. No permissions beyond ACCESS_NETWORK_STATE
 * (install-time, no runtime prompt), no network calls, no third-party IP feed.
 */
class VeraNetIntegrityModule : Module() {

  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  override fun definition() = ModuleDefinition {
    Name("VeraNetIntegrity")

    AsyncFunction("getStatus") {
      val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
      val tunnel = detectTunnel(cm)

      val proxy = detectProxy(cm)
      val ca = caCounts()

      mapOf(
        "vpnActive" to tunnel.active,
        "vpnBasis" to tunnel.basis,
        "proxyConfigured" to proxy.configured,
        "proxyBasis" to proxy.basis,
        "userCaCount" to ca.user,
        "systemCaCount" to ca.system
      )
    }
  }

  private data class Tunnel(val active: Boolean, val basis: String)
  private data class Proxy(val configured: Boolean, val basis: String)
  private data class CaCounts(val user: Int, val system: Int)

  /**
   * Real tunnel interfaces only. Every Linux kernel — so every Android device —
   * carries stub interfaces named tunl0, ip_vti0, gre0, sit0 and friends. A
   * naive startsWith("tun") matches tunl0 and reports a VPN on 100% of
   * handsets, so the name must be a tunnel prefix followed by an index and
   * nothing else, and the interface must actually hold an address.
   */
  private val tunnelName = Regex("^(tun|tap|ppp|ipsec|utun)\\d+$")

  /**
   * TRANSPORT_VPN is the authoritative answer and covers every VpnService app.
   * The interface sweep is the fallback for the case the capability lookup
   * returns nothing (no active network handle yet), and also catches tunnels
   * that never register as the default network.
   */
  private fun detectTunnel(cm: ConnectivityManager?): Tunnel {
    try {
      val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
      if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
        return Tunnel(true, "transport")
      }
    } catch (e: Exception) {
      // fall through to the interface sweep
    }
    return try {
      // tun/tap = OpenVPN & WireGuard, ppp = legacy/L2TP, ipsec/utun = IKEv2.
      val hit = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().any { iface ->
        iface.isUp && !iface.isLoopback &&
          tunnelName.matches(iface.name.lowercase()) &&
          iface.inetAddresses.hasMoreElements()
      }
      if (hit) Tunnel(true, "interface") else Tunnel(false, "none")
    } catch (e: Exception) {
      Tunnel(false, "unavailable")
    }
  }

  /**
   * An explicit HTTP proxy — the usual shape of traffic inspection on Wi-Fi.
   *
   * The JVM properties are checked only as a fallback and only when they name a
   * real host: Android leaves http.proxyHost set to an empty string rather than
   * unsetting it, so "is it non-null" reports a proxy on a device that has none.
   */
  private fun detectProxy(cm: ConnectivityManager?): Proxy {
    try {
      val proxy = cm?.defaultProxy
      val host = proxy?.host.orEmpty()
      if (host.isNotEmpty()) return Proxy(true, "defaultProxy")
    } catch (e: Exception) {
      // fall through to the JVM properties
    }
    return try {
      val http = System.getProperty("http.proxyHost").orEmpty()
      val https = System.getProperty("https.proxyHost").orEmpty()
      if (http.isNotEmpty() || https.isNotEmpty()) Proxy(true, "jvm-props")
      else Proxy(false, "none")
    } catch (e: Exception) {
      Proxy(false, "unavailable")
    }
  }

  /**
   * Count of user-installed root CAs — the classic interception-proxy tell
   * (Burp, mitmproxy, Charles all require one).
   *
   * Read this as capability, not proof. Since Android 7 apps do not trust user
   * CAs for their own traffic unless the app opts in via networkSecurityConfig,
   * so a user CA alone does NOT mean this app's TLS is being read. It means
   * someone deliberately prepared this handset to read TLS — which is why it
   * matters most next to root (where a system CA or a pinning bypass is
   * available anyway) rather than on its own.
   *
   * The count, never the subjects: enterprise MDM CAs are legitimate and the
   * issuer names are needlessly identifying.
   */
  private fun caCounts(): CaCounts {
    return try {
      val ks = KeyStore.getInstance("AndroidCAStore")
      ks.load(null, null)
      val aliases = ks.aliases().toList()
      CaCounts(
        user = aliases.count { it.startsWith("user:") },
        // Reported alongside so the user count can be sanity-checked: a store
        // with no system CAs at all means the read failed in a way the count
        // alone cannot express, not a pristine device.
        system = aliases.count { it.startsWith("system:") }
      )
    } catch (e: Exception) {
      CaCounts(-1, -1) // unreadable — distinct from a genuine zero
    }
  }
}
