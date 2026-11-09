package ru.mayaklight.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import java.net.Inet4Address
import java.net.InetAddress

/** Strictly binds an already-created probe fd to the VPN whose link owns the requested AWG address. */
object MayakProbeSocketBinder {
    @JvmStatic
    fun bindSocket(context: Context, fd: Int, localIpv4: String, interfaceName: String): Boolean {
        if (android.os.Build.VERSION.SDK_INT < 28 || fd < 0 || interfaceName.isBlank()) return false
        val local = try { InetAddress.getByName(localIpv4) } catch (_: Exception) { return false }
        if (local !is Inet4Address || local.hostAddress != localIpv4) return false
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val candidates = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            val lp = cm.getLinkProperties(network) ?: return@mapNotNull null
            if (lp.interfaceName != interfaceName || lp.linkAddresses.none { it.address == local }) return@mapNotNull null
            network
        }
        if (candidates.size != 1) return false
        return try {
            // fromFd duplicates. Closing this PFD closes only the duplicate, never Qt's socket.
            ParcelFileDescriptor.fromFd(fd).use { duplicate ->
                candidates.single().bindSocket(duplicate.fileDescriptor)
            }
            true
        } catch (_: Exception) { false }
    }
}
