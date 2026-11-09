package org.amnezia.vpn.protocol.wireguard

import android.net.VpnService.Builder
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.net.InetAddress
import java.net.Inet4Address
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.isActive
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.amnezia.awg.GoBackend
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.asSequence
import org.amnezia.vpn.util.net.InetEndpoint
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.amnezia.vpn.util.optStringOrNull
import org.json.JSONObject

private const val TAG = "Wireguard"
private const val STATUS_POLL_TIMEOUT_MS = 1_000L
// Mayak recovery: how long a replacement waits for the old backend to close before moving on.
private const val RETIRE_WAIT_MS = 2_000L

/** Own-peer UAPI snapshot. This reports tunnel telemetry, not internet reachability. */
data class AwgTunnelHealth(
    val generation: Long,
    val healthContextId: String,
    val peerPublicKey: String,
    val endpoint: String,
    val localAddress: String,
    val interfaceName: String,
    val latestHandshakeEpochMs: Long,
    val rxTotal: Long,
    val txTotal: Long,
    val valid: Boolean
) {
    fun toJsonString(): String = JSONObject()
        .put("generation", generation.toString())
        .put("healthContextId", healthContextId)
        .put("peerPublicKey", peerPublicKey)
        .put("endpoint", endpoint)
        .put("localAddress", localAddress)
        .put("interfaceName", interfaceName)
        .put("latestHandshakeEpochMs", latestHandshakeEpochMs.toString())
        .put("rxTotal", rxTotal.toString())
        .put("txTotal", txTotal.toString())
        .put("valid", valid)
        .toString()
}

internal data class AwgHealthActivation(
    val handle: Int,
    val generation: Long,
    val contextId: String,
    val peerPublicKey: String,
    val endpoint: String
)

/** Linearizes stop/start against publication, including synchronous metadata lookup. */
internal class AwgHealthPublicationGate {
    private var active: AwgHealthActivation? = null

    @Synchronized fun activate(activation: AwgHealthActivation) { active = activation }
    @Synchronized fun invalidate() { active = null }
    @Synchronized fun isCurrent(activation: AwgHealthActivation): Boolean = active == activation
    @Synchronized fun accepts(health: AwgTunnelHealth): Boolean {
        val activation = active ?: return false
        return activation.contextId.isNotEmpty() && health.healthContextId == activation.contextId &&
            health.generation == activation.generation &&
            health.peerPublicKey.equals(activation.peerPublicKey, ignoreCase = true) &&
            health.endpoint == activation.endpoint
    }
    @Synchronized fun publishIfCurrent(
        activation: AwgHealthActivation,
        mayPublish: () -> Boolean,
        publish: () -> Unit
    ): Boolean {
        if (active != activation || !mayPublish()) return false
        publish()
        return true
    }
}

internal data class AwgPeerStats(
    val publicKey: String,
    val endpoint: String?,
    val handshakeEpochMs: Long?,
    val rxBytes: Long?,
    val txBytes: Long?
) {
    val hasConfirmedHandshake: Boolean
        get() = handshakeEpochMs?.let { it > 0L } == true
}

internal fun parseAwgPeerStats(
    response: String,
    expectedPublicKey: String,
    requireHandshake: Boolean
): AwgPeerStats? {
    var peer: MutableMap<String, String>? = null
    val target = expectedPublicKey.lowercase()
    for (line in response.lineSequence()) {
        if (line.isBlank()) continue
        val separator = line.indexOf('=')
        if (separator <= 0) return null
        val key = line.substring(0, separator)
        val value = line.substring(separator + 1)
        if (key == "public_key") {
            if (peer != null && peer["public_key"] == target) break
            peer = mutableMapOf("public_key" to value.lowercase())
        } else if (peer != null) {
            peer[key] = value
        }
    }

    val ownPeer = peer?.takeIf { it["public_key"] == target } ?: return null
    val handshakeSecondsText = ownPeer["last_handshake_time_sec"]
    val handshakeNanosText = ownPeer["last_handshake_time_nsec"]
    val handshakeSeconds = handshakeSecondsText?.toLongOrNull()
    val handshakeNanos = handshakeNanosText?.toLongOrNull()
    val handshakeEpochMs = if (handshakeSecondsText != null && handshakeNanosText != null &&
        handshakeSeconds != null && handshakeNanos != null && handshakeSeconds >= 0L &&
        handshakeNanos in 0L until 1_000_000_000L &&
        handshakeSeconds <= (Long.MAX_VALUE - handshakeNanos / 1_000_000L) / 1000L) {
        handshakeSeconds * 1000L + handshakeNanos / 1_000_000L
    } else null
    if (requireHandshake && handshakeEpochMs == null) return null
    val rx = ownPeer["rx_bytes"]?.toLongOrNull()?.takeIf { it >= 0L } ?: return null
    val tx = ownPeer["tx_bytes"]?.toLongOrNull()?.takeIf { it >= 0L } ?: return null
    return AwgPeerStats(ownPeer["public_key"]!!, ownPeer["endpoint"], handshakeEpochMs, rx, tx)
}

internal fun matchVpnInterfaceMetadata(
    configuredIpv4: InetAddress,
    candidates: List<Pair<String, List<InetAddress>>>
): Pair<String, String>? {
    if (configuredIpv4 !is Inet4Address) return null
    // Each candidate is one current VPN network; ambiguity cannot establish ownership.
    val interfaceName = candidates.singleOrNull { (name, addresses) ->
        name.isNotBlank() && addresses.any { it == configuredIpv4 }
    }?.first ?: return null
    return (configuredIpv4.hostAddress ?: return null) to interfaceName
}

open class Wireguard : Protocol() {

    @Volatile private var tunnelHandle: Int = -1
    private var config: WireguardConfig? = null // save config for reconnect
    protected open val ifName: String = "amn0"
    private lateinit var scope: CoroutineScope
    private var statusJob: Job? = null
    @Volatile private var backendGeneration: Long = 0L
    // Opaque Qt-owned proof context of the live backend; only Mayak managed recovery reuses it.
    @Volatile private var activeHealthContextId: String? = null
    private val healthPublication = AwgHealthPublicationGate()
    // Dups of the live backend's UDP sockets (Mayak bounded recovery only uses them).
    @Volatile private var activeSockets: List<BackendSocket> = emptyList()
    private val mutableTunnelHealth = MutableStateFlow<AwgTunnelHealth?>(null)
    val tunnelHealth = mutableTunnelHealth.asStateFlow()

    override val statistics: Statistics
        get() {
            val handle = tunnelHandle
            val wgConfig = config
            if (handle == -1 || wgConfig == null) return Statistics.EMPTY_STATISTICS
            val response = runCatching { GoBackend.awgGetConfig(handle) }.getOrNull()
                ?: return Statistics.EMPTY_STATISTICS
            val peer = parseAwgPeerStats(response, wgConfig.publicKeyHex, requireHandshake = false)
                ?: return Statistics.EMPTY_STATISTICS
            val rx = peer.rxBytes ?: return Statistics.EMPTY_STATISTICS
            val tx = peer.txBytes ?: return Statistics.EMPTY_STATISTICS
            return Statistics.build {
                setRxBytes(rx)
                setTxBytes(tx)
            }
        }

    override fun internalInit() {
        if (!isInitialized) loadSharedLibrary(context, "wg-go")
        if (this::scope.isInitialized) {
            healthPublication.invalidate()
            scope.cancel()
        }
        scope = CoroutineScope(Dispatchers.IO)
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val wireguardConfig = parseConfig(config)
        this.config = wireguardConfig
        start(wireguardConfig, vpnBuilder, protect, healthContextId = config.optString("healthContextId").ifBlank { UUID.randomUUID().toString() })
    }

    protected open fun parseConfig(config: JSONObject): WireguardConfig {
        val configData = config.getJSONObject("wireguard_config_data")
        return WireguardConfig.build {
            configWireguard(config, configData)
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    protected fun WireguardConfig.Builder.configWireguard(config: JSONObject, configData: JSONObject) {
        configData.getString("client_ip").split(",").map { address ->
            InetNetwork.parse(address.trim())
        }.forEach(::addAddress)

        config.optStringOrNull("dns1")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        config.optStringOrNull("dns2")?.let { dns ->
            addDnsServer(parseInetAddress(dns.trim()))
        }

        val defRoutes = hashSetOf(
            InetNetwork("0.0.0.0", 0),
            InetNetwork("::", 0)
        )
        val routes = hashSetOf<InetNetwork>()
        configData.getJSONArray("allowed_ips").asSequence<String>().map { route ->
            InetNetwork.parse(route.trim())
        }.forEach(routes::add)
        // if the allowed IPs list contains at least one non-default route, disable global split tunneling
        if (routes.any { it !in defRoutes }) disableSplitTunneling()
        addRoutes(routes)

        configData.optStringOrNull("mtu")?.let { setMtu(it.toInt()) }

        val host = configData.getString("hostName").let { parseInetAddress(it.trim()) }
        val port = configData.getInt("port")
        setEndpoint(InetEndpoint(host, port))

        if (configData.optBoolean("isObfuscationEnabled")) {
            setUseProtocolExtension(true)
            configExtensionParameters(configData)
        }

        configData.optStringOrNull("persistent_keep_alive")?.let { setPersistentKeepalive(it) }
        configData.getString("client_priv_key").let { setPrivateKeyHex(it.base64ToHex()) }
        configData.getString("server_pub_key").let { setPublicKeyHex(it.base64ToHex()) }
        configData.optStringOrNull("psk_key")?.let { setPreSharedKeyHex(it.base64ToHex()) }
    }

    protected fun WireguardConfig.Builder.configExtensionParameters(configData: JSONObject) {
        configData.optStringOrNull("Jc")?.let { setJc(it.toInt()) }
        configData.optStringOrNull("Jmin")?.let { setJmin(it.toInt()) }
        configData.optStringOrNull("Jmax")?.let { setJmax(it.toInt()) }
        configData.optStringOrNull("S1")?.let { setS1(it.toInt()) }
        configData.optStringOrNull("S2")?.let { setS2(it.toInt()) }
        configData.optStringOrNull("S3")?.let { setS3(it.toInt()) }
        configData.optStringOrNull("S4")?.let { setS4(it.toInt()) }
        configData.optStringOrNull("H1")?.trim()?.let { if (it.isNotEmpty()) setH1(it) }
        configData.optStringOrNull("H2")?.trim()?.let { if (it.isNotEmpty()) setH2(it) }
        configData.optStringOrNull("H3")?.trim()?.let { if (it.isNotEmpty()) setH3(it) }
        configData.optStringOrNull("H4")?.trim()?.let { if (it.isNotEmpty()) setH4(it) }
        configData.optStringOrNull("I1")?.let { setI1(it) }
        configData.optStringOrNull("I2")?.let { setI2(it) }
        configData.optStringOrNull("I3")?.let { setI3(it) }
        configData.optStringOrNull("I4")?.let { setI4(it) }
        configData.optStringOrNull("I5")?.let { setI5(it) }
        configData.optStringOrNull("HeaderProtectionKey")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setHeaderProtectionKey(it.base64ToHex()) }
        configData.optStringOrNull("ContentPaddingAddition")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setContentPaddingAddition(it) }
        configData.optStringOrNull("RekeyAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyAfterTime(it) }
        configData.optStringOrNull("RekeyTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRekeyTimeout(it) }
        configData.optStringOrNull("RejectAfterTime")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRejectAfterTime(it) }
        configData.optStringOrNull("KeepaliveTimeout")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setKeepaliveTimeout(it) }
        configData.optStringOrNull("MaxHandshakeAttempts")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setMaxHandshakeAttempts(it) }
        configData.optStringOrNull("RandomTrailers")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setRandomTrailers(it) }
        configData.optStringOrNull("DisableCookies")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { setDisableCookies(it) }
    }

    private fun start(
        config: WireguardConfig,
        vpnBuilder: Builder,
        protect: (Int) -> Boolean,
        stopExistingVpn: Boolean = false,
        healthContextId: String,
        boundedStop: Boolean = false
    ) {
        if (!stopExistingVpn && tunnelHandle != -1) {
            Log.w(TAG, "Tunnel already up")
            return
        }

        // Invalidate callbacks/samples from any prior handle before bringing up this one.
        healthPublication.invalidate()
        statusJob?.cancel()
        statusJob = null
        backendGeneration += 1
        mutableTunnelHealth.value = null

        buildVpnInterface(config, vpnBuilder)

        vpnBuilder.establish().use { tunFd ->
            if (stopExistingVpn && tunnelHandle != -1) {
                if (boundedStop) turnOffVpnBounded() else turnOffVpn()
            }
            if (tunFd == null) {
                throw VpnStartException("Create VPN interface: permission not granted or revoked")
            }
            Log.i(TAG, "awg-go backend ${GoBackend.awgVersion()}")
            tunnelHandle = GoBackend.awgTurnOn(ifName, tunFd.detachFd(), config.toWgUserspaceString())
        }

        if (tunnelHandle < 0) {
            tunnelHandle = -1
            throw VpnStartException("Wireguard tunnel creation error")
        }

        val socketV4 = GoBackend.awgGetSocketV4(tunnelHandle)
        val socketV6 = GoBackend.awgGetSocketV6(tunnelHandle)
        if (!protect(socketV4) || !protect(socketV6)) {
            GoBackend.awgTurnOff(tunnelHandle)
            tunnelHandle = -1
            throw VpnStartException("Protect VPN interface: permission not granted or revoked")
        }
        activeSockets = listOfNotNull(dupBackendSocket(socketV4), dupBackendSocket(socketV6))
        val activation = AwgHealthActivation(tunnelHandle, backendGeneration, healthContextId,
            config.publicKeyHex, config.endpoint.toString())
        activeHealthContextId = healthContextId
        healthPublication.activate(activation)
        launchStatusJob(config, activation)
    }

    fun isCurrentTunnelHealth(health: AwgTunnelHealth): Boolean = healthPublication.accepts(health)

    private fun launchStatusJob(config: WireguardConfig, activation: AwgHealthActivation) {
        Log.d(TAG, "Launch status job")
        val handle = activation.handle
        val generation = activation.generation
        val expectedPeer = activation.peerPublicKey
        statusJob = scope.launch {
            val samplingContext = coroutineContext
            while (samplingContext.isActive && healthPublication.isCurrent(activation)) {
                val response = runCatching { GoBackend.awgGetConfig(handle) }.getOrNull()
                val peer = response?.let { parseAwgPeerStats(it, expectedPeer, requireHandshake = true) }
                if (tunnelHandle != handle || backendGeneration != generation) break
                val handshakeEpochMs = peer?.handshakeEpochMs
                val localVpnMetadata = findVpnInterfaceMetadata(config)
                val localAddress = localVpnMetadata?.first.orEmpty()
                val interfaceName = localVpnMetadata?.second.orEmpty()
                val endpoint = peer?.endpoint?.takeIf { it.isNotBlank() }
                    ?: config.endpoint.toString()
                val valid = peer != null && handshakeEpochMs != null &&
                    peer.rxBytes != null && peer.txBytes != null &&
                    endpoint.isNotBlank() && localAddress.isNotBlank() && interfaceName.isNotBlank()
                val health = if (valid) {
                    AwgTunnelHealth(
                        generation = generation,
                        healthContextId = activation.contextId,
                        peerPublicKey = peer!!.publicKey,
                        endpoint = endpoint,
                        localAddress = localAddress,
                        interfaceName = interfaceName,
                        latestHandshakeEpochMs = handshakeEpochMs!!,
                        rxTotal = peer.rxBytes!!,
                        txTotal = peer.txBytes!!,
                        valid = true
                    )
                } else {
                    AwgTunnelHealth(
                        generation = generation,
                        healthContextId = activation.contextId,
                        peerPublicKey = expectedPeer,
                        endpoint = endpoint,
                        localAddress = localAddress,
                        interfaceName = interfaceName,
                        latestHandshakeEpochMs = 0L,
                        rxTotal = 0L,
                        txTotal = 0L,
                        valid = false
                    )
                }

                // Recheck cancellation, handle, generation and opaque context AFTER metadata.
                // invalidate() and this publication are serialized by the same monitor.
                val published = healthPublication.publishIfCurrent(activation, {
                    samplingContext.isActive && tunnelHandle == handle && backendGeneration == generation
                }) {
                    mutableTunnelHealth.value = health
                    if (valid && peer?.hasConfirmedHandshake == true) state.value = CONNECTED
                }
                if (!published) break
                delay(STATUS_POLL_TIMEOUT_MS)
            }
        }
    }

    private fun findVpnInterfaceMetadata(config: WireguardConfig): Pair<String, String>? {
        val ipv4 = config.addresses.firstOrNull { it.isIpv4 }?.address ?: return null
        val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val candidates = connectivity.allNetworks.mapNotNull { network: Network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            val properties: LinkProperties = connectivity.getLinkProperties(network) ?: return@mapNotNull null
            properties.interfaceName?.let { name -> name to properties.linkAddresses.map { it.address } }
        }
        return matchVpnInterfaceMetadata(ipv4, candidates)
    }

    private fun turnOffVpn() {
        healthPublication.invalidate()
        statusJob?.cancel()
        statusJob = null
        backendGeneration += 1
        mutableTunnelHealth.value = null
        val handleToClose = tunnelHandle
        GoBackend.awgTurnOff(handleToClose)
        tunnelHandle = -1
        activeSockets.forEach { it.closeQuietly() }
        activeSockets = emptyList()
    }

    fun managedIsBackendOff(): Boolean = tunnelHandle == -1
    fun managedStopAndConfirm(): Boolean = try {
        stopVpn()
        tunnelHandle == -1
    } catch (_: Exception) { false }

    /**
     * Mayak bounded close of the backend being replaced by a soft recovery. Closing an AWG
     * device can block for a long time right after a network change (seen on device: 15 s and
     * 12 min). By then establish() has already moved Android's routes to the new TUN, so an
     * unbounded close left the phone without internet until the UI was opened. The close runs
     * on its own thread; normally it finishes within the wait and the order stays as before.
     * If it does not, the old backend's UDP sockets are shut for sending (it would otherwise
     * keep handshaking with the same key and pull the server's endpoint away from the new
     * backend) and the replacement continues. The stuck thread is left to finish on its own.
     */
    private fun turnOffVpnBounded() {
        healthPublication.invalidate()
        statusJob?.cancel()
        statusJob = null
        backendGeneration += 1
        mutableTunnelHealth.value = null
        val handleToClose = tunnelHandle
        val socketsToClose = activeSockets
        activeSockets = emptyList()
        tunnelHandle = -1
        if (handleToClose == -1) {
            socketsToClose.forEach { it.closeQuietly() }
            return
        }
        val startedAt = android.os.SystemClock.elapsedRealtime()
        val closer = Thread({
            GoBackend.awgTurnOff(handleToClose)
            socketsToClose.forEach { it.closeQuietly() }
            val elapsed = android.os.SystemClock.elapsedRealtime() - startedAt
            if (elapsed >= RETIRE_WAIT_MS) Log.i(TAG, "MayakNet event=retire_done elapsed_ms=$elapsed")
        }, "awg-retire")
        closer.isDaemon = true
        closer.start()
        // awgTurnOff drops the handle from the backend's table as its first step, so after the
        // wait the next awgTurnOn never races that table update.
        closer.join(RETIRE_WAIT_MS)
        if (!closer.isAlive) return
        val silenced = socketsToClose.count { it.shutdownSend() }
        Log.w(TAG, "MayakNet event=retire_slow waited_ms=$RETIRE_WAIT_MS silenced=$silenced")
    }

    /** Own dup of a backend UDP socket: lets a stuck old backend be silenced without fd reuse. */
    private class BackendSocket(private val dup: ParcelFileDescriptor) {
        fun shutdownSend(): Boolean = try {
            Os.shutdown(dup.fileDescriptor, OsConstants.SHUT_WR)
            true
        } catch (e: ErrnoException) {
            // Unconnected UDP reports ENOTCONN but the kernel still marks the socket shut.
            e.errno == OsConstants.ENOTCONN
        } catch (_: Exception) { false }

        fun closeQuietly() { runCatching { dup.close() } }
    }

    private fun dupBackendSocket(fd: Int): BackendSocket? =
        if (fd < 0) null else runCatching { BackendSocket(ParcelFileDescriptor.fromFd(fd)) }.getOrNull()

    /**
     * Mayak managed recovery: replace the live AWG backend (new handle, new UDP socket and
     * source port) with the same config and the same Qt-owned proof context. The new TUN is
     * established before the old handle is closed, so Android never drops the VPN and no
     * traffic leaves outside it. Returns true only when a new backend is running.
     */
    fun managedRecover(vpnBuilder: Builder, protect: (Int) -> Boolean, expectedContextId: String): Boolean {
        val config = this.config ?: return false
        val context = activeHealthContextId ?: return false
        if (context != expectedContextId || tunnelHandle == -1) return false
        val ok = try {
            start(config, vpnBuilder, protect, true, healthContextId = context, boundedStop = true)
            tunnelHandle != -1
        } catch (e: Exception) {
            Log.e(TAG, "Managed recovery failed: ${e.javaClass.simpleName}")
            false
        }
        if (!ok && tunnelHandle == -1) {
            // The old backend is already closed and no new one runs: never stay "connected"
            // without a tunnel. Report the honest state so the owner/notification can react.
            healthPublication.invalidate()
            activeHealthContextId = null
            state.value = DISCONNECTED
        }
        return ok
    }

    override fun stopVpn() {
        healthPublication.invalidate()
        activeHealthContextId = null
        if (tunnelHandle == -1) {
            Log.w(TAG, "Tunnel already down")
            return
        }
        turnOffVpn()
        state.value = DISCONNECTED
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        val config = this.config ?: throw VpnException("Reconnect config is empty")
        // Autonomous backend restart cannot reuse a prior Qt-owned proof context.
        start(config, vpnBuilder, protect, true, healthContextId = UUID.randomUUID().toString())
    }
}
