package org.amnezia.vpn

import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.awg.Awg
import org.amnezia.vpn.protocol.openvpn.OpenVpn
import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.xray.Xray

enum class VpnProto(
    val label: String,
    val processName: String,
    val serviceClass: Class<out AmneziaVpnService>
) {
    WIREGUARD(
        "WireGuard",
        BuildConfig.APPLICATION_ID + ":amneziaAwgService",
        AwgService::class.java
    ) {
        override fun createProtocol(): Protocol = Wireguard()
    },

    AWG(
        "AmneziaWG",
        BuildConfig.APPLICATION_ID + ":amneziaAwgService",
        AwgService::class.java
    ) {
        override fun createProtocol(): Protocol = Awg()
    },

    OPENVPN(
        "OpenVPN",
        BuildConfig.APPLICATION_ID + ":amneziaOpenVpnService",
        OpenVpnService::class.java
    ) {
        override fun createProtocol(): Protocol = OpenVpn()
    },

    XRAY(
        "XRay",
        BuildConfig.APPLICATION_ID + ":amneziaXrayService",
        XrayService::class.java
    ) {
        override fun createProtocol(): Protocol = Xray.instance
    },

    SSXRAY(
        "SSXRay",
        BuildConfig.APPLICATION_ID + ":amneziaXrayService",
        XrayService::class.java
    ) {
        override fun createProtocol(): Protocol = Xray.instance
    };

    private var _protocol: Protocol? = null
    val protocol: Protocol
        get() {
            if (_protocol == null) _protocol = createProtocol()
            return _protocol ?: throw AssertionError("Set to null by another thread")
        }

    protected abstract fun createProtocol(): Protocol

    /** Managed AWG ownership cannot reuse an instance whose callbacks retain a prior state sink. */
    fun newManagedProtocol(): Protocol = when (this) {
        WIREGUARD -> Wireguard()
        AWG -> Awg()
        // Mayak Xray path: the process-wide Xray engine; initialize() re-binds its state sink.
        XRAY -> Xray.instance
        else -> throw IllegalArgumentException("Managed lifecycle requires WireGuard, AmneziaWG or Xray")
    }

    companion object {
        fun get(protocolName: String): VpnProto = VpnProto.valueOf(protocolName.uppercase())
    }
}
