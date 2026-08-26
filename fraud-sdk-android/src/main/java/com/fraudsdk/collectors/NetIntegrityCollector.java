package com.fraudsdk.collectors;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;

import org.json.JSONObject;

import java.net.NetworkInterface;
import java.security.KeyStore;
import java.util.Collections;
import java.util.regex.Pattern;

/**
 * Transport-integrity snapshot: is this session's traffic tunnelled, and is
 * anything positioned to read it? Java port of the Expo SDK's
 * VeraNetIntegrityModule — same fields, same detection rules, so the server's
 * VPN_ACTIVE / PROXY_CONFIGURED / MITM_CA_INSTALLED signals score identically
 * whichever SDK the bank shipped.
 *
 * Nothing here blocks: a VPN is ordinary consumer behaviour, and the weights
 * live server-side. Reads local system state only — no permissions beyond
 * ACCESS_NETWORK_STATE, no network calls, no IP-reputation feed.
 */
public final class NetIntegrityCollector {

    /**
     * Real tunnel interfaces only. Every Linux kernel — so every Android
     * device — carries stub interfaces named tunl0, ip_vti0, gre0, sit0. A
     * naive startsWith("tun") matches tunl0 and reports a VPN on 100% of
     * handsets (measured, not hypothetical), so the name must be a tunnel
     * prefix plus an index and nothing else, and the interface must actually
     * hold an address.
     */
    private static final Pattern TUNNEL_NAME =
            Pattern.compile("^(tun|tap|ppp|ipsec|utun)\\d+$");

    private final Context app;

    public NetIntegrityCollector(Context app) {
        this.app = app;
    }

    public JSONObject collect() {
        JSONObject o = new JSONObject();
        try {
            ConnectivityManager cm =
                    (ConnectivityManager) app.getSystemService(Context.CONNECTIVITY_SERVICE);

            String vpnBasis = detectTunnel(cm);
            o.put("vpnActive", !"none".equals(vpnBasis) && !"unavailable".equals(vpnBasis));
            o.put("vpnBasis", vpnBasis);

            String proxyBasis = detectProxy(cm);
            o.put("proxyConfigured", !"none".equals(proxyBasis) && !"unavailable".equals(proxyBasis));
            o.put("proxyBasis", proxyBasis);

            int[] ca = caCounts();
            o.put("userCaCount", ca[0]);
            o.put("systemCaCount", ca[1]);
        } catch (Exception ignored) {}
        return o;
    }

    /** "transport" | "interface" | "none" | "unavailable". */
    private String detectTunnel(ConnectivityManager cm) {
        if (Build.VERSION.SDK_INT >= 23 && cm != null) {
            try {
                Network active = cm.getActiveNetwork();
                NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return "transport";
                }
            } catch (Exception ignored) {
                // fall through to the interface sweep
            }
        }
        try {
            // tun/tap = OpenVPN & WireGuard, ppp = legacy/L2TP, ipsec/utun = IKEv2.
            for (NetworkInterface iface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (iface.isUp() && !iface.isLoopback()
                        && TUNNEL_NAME.matcher(iface.getName().toLowerCase()).matches()
                        && iface.getInetAddresses().hasMoreElements()) {
                    return "interface";
                }
            }
            return "none";
        } catch (Exception e) {
            return "unavailable";
        }
    }

    /**
     * "defaultProxy" | "jvm-props" | "none" | "unavailable". The JVM
     * properties are a fallback and only count when they name a real host:
     * Android leaves http.proxyHost set to an empty string rather than
     * unsetting it, so a null check reports a proxy on a device with none.
     */
    private String detectProxy(ConnectivityManager cm) {
        if (Build.VERSION.SDK_INT >= 23 && cm != null) {
            try {
                ProxyInfo proxy = cm.getDefaultProxy();
                if (proxy != null && proxy.getHost() != null && !proxy.getHost().isEmpty()) {
                    return "defaultProxy";
                }
            } catch (Exception ignored) {
                // fall through to the JVM properties
            }
        }
        try {
            String http = System.getProperty("http.proxyHost");
            String https = System.getProperty("https.proxyHost");
            if ((http != null && !http.isEmpty()) || (https != null && !https.isEmpty())) {
                return "jvm-props";
            }
            return "none";
        } catch (Exception e) {
            return "unavailable";
        }
    }

    /**
     * {user, system} CA counts. A user-installed root CA is the
     * interception-proxy tell (Burp, mitmproxy, Charles all need one) — read
     * as capability, not proof: since Android 7 apps do not trust user CAs
     * without opting in. The system count is the sanity check the server
     * requires: a store reporting zero system CAs did not read successfully,
     * whatever the user count says. {-1, -1} = unreadable, distinct from zero.
     */
    private int[] caCounts() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            int user = 0, system = 0;
            for (String alias : Collections.list(ks.aliases())) {
                if (alias.startsWith("user:")) user++;
                else if (alias.startsWith("system:")) system++;
            }
            return new int[] { user, system };
        } catch (Exception e) {
            return new int[] { -1, -1 };
        }
    }
}
