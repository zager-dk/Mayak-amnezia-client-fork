package org.amnezia.vpn

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.Process
import androidx.annotation.MainThread
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.ProtocolState.RECONNECTING
import org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.putStatus
import org.amnezia.vpn.util.LoadLibraryException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
import org.amnezia.vpn.util.net.NetworkState
import org.amnezia.vpn.util.net.TrafficStats
import org.json.JSONException
import org.json.JSONObject

private const val TAG = "AmneziaVpnService"

const val ACTION_DISCONNECT = "org.amnezia.vpn.action.disconnect"
const val ACTION_CONNECT = "org.amnezia.vpn.action.connect"

const val MSG_VPN_CONFIG = "VPN_CONFIG"
const val MSG_ERROR = "ERROR"
const val MSG_SAVE_LOGS = "SAVE_LOGS"
const val MSG_CLIENT_NAME = "CLIENT_NAME"
const val MSG_AWG_TUNNEL_HEALTH = "AWG_TUNNEL_HEALTH"
const val MSG_MANAGED_RESULT = "MANAGED_RESULT"
const val MSG_MANAGED_TICKET = "MANAGED_TICKET"
const val MSG_HEALTH_CONTEXT_ID = "HEALTH_CONTEXT_ID"

const val AFTER_PERMISSION_CHECK = "AFTER_PERMISSION_CHECK"
private const val PREFS_CONFIG_KEY = "LAST_CONF"
private const val PREFS_SERVER_NAME = "LAST_SERVER_NAME"
private const val PREFS_SERVER_INDEX = "LAST_SERVER_INDEX"
// private const val STATISTICS_SENDING_TIMEOUT = 1000L
private const val TRAFFIC_STATS_UPDATE_TIMEOUT = 1000L
private const val STATUS_HEALTH_UPDATE_TIMEOUT = 1000L
private const val DISCONNECT_TIMEOUT = 5000L
private const val STOP_SERVICE_TIMEOUT = 5000L

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private lateinit var mainScope: CoroutineScope
    private lateinit var connectionScope: CoroutineScope
    private var isServiceBound = false
    private var vpnProto: VpnProto? = null
    private class ConnectionSession(
        val source: ManagedProtocolState<org.amnezia.vpn.protocol.ProtocolState>,
        val protocol: Protocol?
    )
    @Volatile private var activeSession = ConnectionSession(ManagedProtocolState("", "", UNKNOWN), null)
    private val protocolState get() = activeSession.source.state
    private var protocolStateJob: Job? = null
    private var serverName: String? = null
    private var serverIndex: Int = -1

    private val isConnected
        get() = protocolState.value == CONNECTED

    private val isDisconnected
        get() = protocolState.value == DISCONNECTED

    private val isUnknown
        get() = protocolState.value == UNKNOWN

    private val managedStarts = ManagedActivationGate()
    @Volatile private var activeControlIdentity = ""
    @Volatile private var activeManagedTicket = ""
    @Volatile private var managedRequired = false
    private var connectionJob: Job? = null
    private var disconnectionJob: Job? = null
    private var trafficStatsUpdateJob: Job? = null
    private var awgHealthSendingJob: Job? = null
    // private var statisticsSendingJob: Job? = null
    private lateinit var networkState: NetworkState
    private lateinit var trafficStats: TrafficStats
    private var controlReceiver: BroadcastReceiver? = null
    private var notificationStateReceiver: BroadcastReceiver? = null
    private var screenOnReceiver: BroadcastReceiver? = null
    private var screenOffReceiver: BroadcastReceiver? = null
    private val clientMessengers = ConcurrentHashMap<Messenger, IpcMessenger>()

    private val isActivityConnected
        get() = clientMessengers.any { it.value.name == ACTIVITY_MESSENGER_NAME }

    private fun connectionExceptionHandler(session: ConnectionSession) = CoroutineExceptionHandler { _, e ->
        mainScope.launch {
            if (!session.source.isCurrent(activeSession.source)) return@launch
            connectionJob?.cancel()
            connectionJob = null
            disconnectionJob?.cancel()
            disconnectionJob = null
            session.source.state.value = DISCONNECTED
            when (e) {
                is IllegalArgumentException,
                is VpnStartException,
                is VpnException -> onError(e.message ?: e.toString(), session)

                is JSONException,
                is BadConfigException -> onError("VPN config format error: ${e.message}", session)

                is LoadLibraryException -> onError("${e.message}. Caused: ${e.cause?.message}", session)

                is UnknownHostException -> onError("Unknown host", session)

                else -> throw e
            }
        }
    }

    private val actionMessageHandler: Handler by lazy(NONE) {
        object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val action = msg.extractIpcMessage<Action>()
                Log.d(TAG, "Handle action: $action")
                when (action) {
                    Action.REGISTER_CLIENT -> {
                        val clientName = msg.data.getString(MSG_CLIENT_NAME)
                        val messenger = IpcMessenger(msg.replyTo, clientName)
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        // if (clientName == ACTIVITY_MESSENGER_NAME && isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            // if (it.name == ACTIVITY_MESSENGER_NAME) stopSendingStatistics()
                        }
                    }

                    Action.CONNECT -> {
                        connect(msg.data.getString(MSG_VPN_CONFIG))
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.MANAGED_STOP -> managedStop(msg)
                    Action.MANAGED_INSPECT -> managedInspect(msg)

                    Action.REQUEST_STATUS -> {
                        clientMessengers[msg.replyTo]?.let { clientMessenger ->
                            clientMessenger.send {
                                ServiceEvent.STATUS.packToMessage {
                                    putStatus(this@AmneziaVpnService.protocolState.value)
                                }
                            }
                        }
                    }

                    Action.NOTIFICATION_PERMISSION_GRANTED -> {
                        enableNotification()
                    }

                    Action.SET_SAVE_LOGS -> {
                        Log.saveLogs = msg.data.getBoolean(MSG_SAVE_LOGS)
                    }
                }
            }
        }
    }

    private val vpnServiceMessenger: Messenger by lazy(NONE) {
        Messenger(actionMessageHandler)
    }

    /**
     * Notification setup
     */
    private val foregroundServiceTypeCompat
        get() = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> FOREGROUND_SERVICE_TYPE_MANIFEST
            else -> 0
        }

    private val serviceNotification: ServiceNotification by lazy(NONE) { ServiceNotification(this) }

    /**
     * Service overloaded methods
     */
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Create Amnezia VPN service")
        mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        loadServerData()
        launchProtocolStateHandler(activeSession)
        networkState = NetworkState(this, ::reconnect)
        trafficStats = TrafficStats()
        registerBroadcastReceivers()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val isAlwaysOn = intent != null && intent.action == SERVICE_INTERFACE

        if (isAlwaysOn) {
            Log.d(TAG, "Start service via Always-on")
            connect()
        } else if (intent?.getBooleanExtra(AFTER_PERMISSION_CHECK, false) == true) {
            Log.d(TAG, "Start service after permission check")
            connect()
        } else {
            Log.d(TAG, "Start service")
            val config = intent?.getStringExtra(MSG_VPN_CONFIG)
            if (config != null && parseConfigToJson(config)?.optString("managedTicket").orEmpty().isNotBlank()) {
                // Start-service intents can be redelivered out of order. They
                // cannot activate managed work: live Activity Messenger CONNECT
                // is required, ordered on the same channel as stop/inspection.
                pendingVpnConfig = config
            } else connect(config)
        }
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID,
            serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
            foregroundServiceTypeCompat
        )
        return START_REDELIVER_INTENT
    }

    override fun onBind(intent: Intent?): IBinder? {
        Log.d(TAG, "onBind by $intent")
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        isServiceBound = true
        return vpnServiceMessenger.binder
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.d(TAG, "onUnbind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            if (clientMessengers.isEmpty()) {
                isServiceBound = false
                if (isUnknown || isDisconnected) stopService()
            }
        }
        return true
    }

    override fun onRebind(intent: Intent?) {
        Log.d(TAG, "onRebind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            isServiceBound = true
        }
        super.onRebind(intent)
    }

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        // Calls to onRevoke() method may not happen on the main thread of the process
        val revokedSession = activeSession
        mainScope.launch {
            if (revokedSession.source.isCurrent(activeSession.source)) disconnect()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Destroy service")
        unregisterBroadcastReceivers()
        runBlocking {
            disconnect()
            disconnectionJob?.join()
        }
        connectionScope.cancel()
        mainScope.cancel()
        super.onDestroy()
    }

    private fun stopService() {
        Log.d(TAG, "Stop service")
        // the coroutine below will be canceled during the onDestroy call
        mainScope.launch {
            delay(STOP_SERVICE_TIMEOUT)
            Log.w(TAG, "Stop service timeout, kill process")
            Process.killProcess(Process.myPid())
        }
        stopSelf()
    }

    private fun registerBroadcastReceivers() {
        Log.d(TAG, "Register broadcast receivers")
        controlReceiver = registerBroadcastReceiver(
            arrayOf(ACTION_CONNECT, ACTION_DISCONNECT), ContextCompat.RECEIVER_NOT_EXPORTED
        ) {
            it?.action?.let { action ->
                Log.v(TAG, "Broadcast request received: $action")
                when (action) {
                    ACTION_CONNECT -> connect()
                    ACTION_DISCONNECT -> disconnect()
                    else -> Log.w(TAG, "Unknown action received: $action")
                }
            }
        }

        notificationStateReceiver = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            registerBroadcastReceiver(
                arrayOf(
                    NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED,
                    NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED
                )
            ) {
                val state = it?.getBooleanExtra(NotificationManager.EXTRA_BLOCKED_STATE, false)
                Log.v(TAG, "Notification state changed: ${it?.action}, blocked = $state")
                if (state == false) {
                    enableNotification()
                } else {
                    disableNotification()
                }
            }
        } else null

        registerScreenStateBroadcastReceivers()
    }

    private fun registerScreenStateBroadcastReceivers() {
        if (serviceNotification.isNotificationEnabled()) {
            Log.d(TAG, "Register screen state broadcast receivers")
            screenOnReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_ON) {
                if (isConnected && serviceNotification.isNotificationEnabled()) startTrafficStatsUpdateJob()
            }

            screenOffReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_OFF) {
                stopTrafficStatsUpdateJob()
            }
        }
    }

    private fun unregisterScreenStateBroadcastReceivers() {
        Log.d(TAG, "Unregister screen state broadcast receivers")
        unregisterBroadcastReceiver(screenOnReceiver)
        unregisterBroadcastReceiver(screenOffReceiver)
        screenOnReceiver = null
        screenOffReceiver = null
    }

    private fun unregisterBroadcastReceivers() {
        Log.d(TAG, "Unregister broadcast receivers")
        unregisterBroadcastReceiver(controlReceiver)
        unregisterBroadcastReceiver(notificationStateReceiver)
        unregisterScreenStateBroadcastReceivers()
        controlReceiver = null
        notificationStateReceiver = null
    }

    /**
     * Methods responsible for processing VPN connection
     */
    private fun launchProtocolStateHandler(session: ConnectionSession) {
        protocolStateJob?.cancel()
        protocolStateJob = mainScope.launch {
            // drop first default UNKNOWN state
            session.source.state.drop(1).collect { protocolState ->
                if (!session.source.isCurrent(activeSession.source)) return@collect
                val statusIdentity = session.source.identity
                Log.d(TAG, "Protocol state changed: $protocolState")

                serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState)

                clientMessengers.send {
                    ServiceEvent.STATUS_CHANGED.packToMessage {
                        putStatus(protocolState)
                        if (statusIdentity.ticket != null && statusIdentity.context != null) {
                            putString(MSG_MANAGED_TICKET, statusIdentity.ticket)
                            putString(MSG_HEALTH_CONTEXT_ID, statusIdentity.context)
                        }
                    }
                }

                VpnStateStore.store { VpnState(protocolState, serverName, serverIndex, vpnProto) }

                // DataStore may suspend while the next session is activated.
                if (!session.source.isCurrent(activeSession.source)) return@collect

                when (protocolState) {
                    CONNECTED -> {
                        networkState.bindNetworkListener()
                        // if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                    }

                    DISCONNECTED -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        // stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        // stopSendingStatistics()
                    }

                    RECONNECTING -> {
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        // stopSendingStatistics()
                    }

                    CONNECTING, UNKNOWN -> {}
                }
            }
        }
    }

/*  @MainThread
    private fun launchSendingStatistics() {
        if (isServiceBound && isConnected) {
            statisticsSendingJob = mainScope.launch {
                while (true) {
                    clientMessenger.send {
                        ServiceEvent.STATISTICS_UPDATE.packToMessage {
                            putStatistics(protocol?.statistics ?: Statistics.EMPTY_STATISTICS)
                        }
                    }
                    delay(STATISTICS_SENDING_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopSendingStatistics() {
        statisticsSendingJob?.cancel()
    } */

    @MainThread
    private fun enableNotification() {
        registerScreenStateBroadcastReceivers()
        serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState.value)
        launchTrafficStatsUpdate()
    }

    @MainThread
    private fun disableNotification() {
        unregisterScreenStateBroadcastReceivers()
        stopTrafficStatsUpdateJob()
    }

    @MainThread
    private fun launchTrafficStatsUpdate() {
        stopTrafficStatsUpdateJob()
        if (isConnected &&
            serviceNotification.isNotificationEnabled() &&
            getSystemService<PowerManager>()?.isInteractive != false
        ) {
            Log.v(TAG, "Launch traffic stats update")
            trafficStats.reset()
            startTrafficStatsUpdateJob()
        }
    }

    @MainThread
    private fun startTrafficStatsUpdateJob() {
        if (trafficStatsUpdateJob == null && trafficStats.isSupported()) {
            Log.d(TAG, "Start traffic stats update")
            trafficStatsUpdateJob = mainScope.launch {
                while (true) {
                    trafficStats.getSpeed().let { speed ->
                        if (isConnected) {
                            serviceNotification.updateSpeed(speed)
                        }
                    }
                    delay(TRAFFIC_STATS_UPDATE_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopTrafficStatsUpdateJob() {
        Log.d(TAG, "Stop traffic stats update")
        trafficStatsUpdateJob?.cancel()
        trafficStatsUpdateJob = null
    }

    @MainThread
    private fun launchAwgHealthSending(protocol: Wireguard) {
        stopAwgHealthSending()
        awgHealthSendingJob = mainScope.launch {
            while (isActive && protocolState.value !in setOf(DISCONNECTED, DISCONNECTING, RECONNECTING, UNKNOWN)) {
                protocol.tunnelHealth.value?.takeIf { health ->
                    protocol === activeSession.protocol && protocol.isCurrentTunnelHealth(health)
                }?.let { health ->
                    clientMessengers.values
                        .filter { it.name == ACTIVITY_MESSENGER_NAME }
                        .forEach { messenger ->
                            messenger.send {
                                ServiceEvent.AWG_HEALTH_UPDATE.packToMessage {
                                    putString(MSG_AWG_TUNNEL_HEALTH, health.toJsonString())
                                }
                            }
                        }
                }
                delay(STATUS_HEALTH_UPDATE_TIMEOUT)
            }
        }
    }

    @MainThread
    private fun stopAwgHealthSending() {
        awgHealthSendingJob?.cancel()
        awgHealthSendingJob = null
    }

    private var pendingVpnConfig: String? = null

    @MainThread
    private fun connect(vpnConfig: String? = null) {
        if (vpnConfig == null) {
            connectToVpn(pendingVpnConfig ?: Prefs.load(PREFS_CONFIG_KEY))
        } else {
            val persisted = parseConfigToJson(vpnConfig)?.apply {
                remove("healthContextId")
                if (optString("managedTicket").isNotBlank()) put("managedRequired", true)
                remove("managedTicket")
            }?.toString().orEmpty()
            Prefs.save(PREFS_CONFIG_KEY, persisted)
            pendingVpnConfig = vpnConfig
            connectToVpn(vpnConfig)
        }
    }

    @MainThread
    private fun connectToVpn(vpnConfig: String) {
        if (isConnected || protocolState.value == CONNECTING) return

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return
        }

        try {
            vpnProto = VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return
        }

        val managedTicket = config.optString("managedTicket")
        managedRequired = config.optBoolean("managedRequired") || managedTicket.isNotBlank()
        if (managedRequired && managedTicket.isBlank()) return // restored managed work has no live authority
        val ticket = managedTicket.ifBlank { "legacy:" + java.util.UUID.randomUUID() }
        val previousSession = activeSession
        // Keep the old backend addressable until its stop has actually completed.
        // Normal managed replacement reaches here only after its exact stop ACK.
        if ((previousSession.protocol as? Wireguard)?.managedIsBackendOff() == false || connectionJob?.isActive == true) {
            onError("Previous VPN session is not stopped", previousSession)
            return
        }
        if (!managedStarts.begin(ticket)) return
        val protocol = try {
            if (managedTicket.isNotBlank()) vpnProto!!.newManagedProtocol() else vpnProto!!.protocol
        } catch (e: IllegalArgumentException) {
            onError(e.message.orEmpty())
            return
        }
        activeManagedTicket = managedTicket
        val controlIdentity = config.optString("healthContextId").ifBlank { java.util.UUID.randomUUID().toString() }
        config.put("healthContextId", controlIdentity)
        activeControlIdentity = controlIdentity
        val session = ConnectionSession(ManagedProtocolState(managedTicket, controlIdentity, UNKNOWN), protocol)
        activeSession = session
        launchProtocolStateHandler(session)
        session.source.state.value = CONNECTING

        if (!checkPermission()) {
            protocolState.value = DISCONNECTED
            return
        }

        pendingVpnConfig = null
        val previousDisconnection = disconnectionJob
        connectionJob = connectionScope.launch(connectionExceptionHandler(session)) {
            previousDisconnection?.join()
            if (!isActive || !session.source.isCurrent(activeSession.source) || !managedStarts.accepts(ticket)) return@launch
            protocol.initialize(applicationContext, session.source.state) { error -> onError(error, session) }
            if (!isActive || !session.source.isCurrent(activeSession.source) || !managedStarts.commit(ticket)) return@launch
            protocol.startVpn(config, Builder(), ::protect)
            (protocol as? Wireguard)?.let { awg -> mainScope.launch {
                if (session.source.isCurrent(activeSession.source)) launchAwgHealthSending(awg)
            } }
        }
    }

    @MainThread
    private fun disconnect() {
        managedStarts.invalidateAll()
        pendingVpnConfig = null
        stopAwgHealthSending()
        if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return

        Log.d(TAG, "Stop VPN connection")

        protocolState.value = DISCONNECTING
        val session = activeSession
        val connectionToCancel = connectionJob
        disconnectionJob = connectionScope.launch(connectionExceptionHandler(session)) {
            connectionToCancel?.cancelAndJoin()
            if (connectionJob === connectionToCancel) connectionJob = null

            session.protocol?.stopVpn()

            try {
                withTimeout(DISCONNECT_TIMEOUT) {
                    // waiting for disconnect state
                    session.source.state.first { it == DISCONNECTED }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "Disconnect timeout")
                if (session.source.isCurrent(activeSession.source)) stopService()
            }
        }
    }

    private fun sendManaged(msg: Message, result: JSONObject) {
        result.put("owner", "MayakVpnAwgLifecycleV1")
        msg.replyTo?.let { target -> IpcMessenger(target).send {
            ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result.toString()) }
        } }
    }

    @MainThread
    private fun managedStop(msg: Message) {
        val request = msg.data.getString("stopRequestId").orEmpty()
        val identity = msg.data.getString("healthContextId").orEmpty()
        val ticket = msg.data.getString("managedTicket").orEmpty()
        if (request.length != 64 || identity.isBlank()) return
        if (identity != activeControlIdentity || (ticket != activeManagedTicket && ticket != "recovery:" + identity)) {
            sendManaged(msg, JSONObject().put("type", "managedStopped").put("stopRequestId", request)
                .put("healthContextId", identity).put("stopped", false))
            return
        }
        managedStarts.invalidateAll()
        pendingVpnConfig = null
        connectionJob?.cancel()
        stopAwgHealthSending()
        val session = activeSession
        val connectionToCancel = connectionJob
        val previousDisconnection = disconnectionJob
        mainScope.launch {
            var stopped = false
            try {
                withTimeout(3000) {
                    connectionToCancel?.cancelAndJoin()
                    if (connectionJob === connectionToCancel) connectionJob = null
                    previousDisconnection?.join()
                    if (session.source.isCurrent(activeSession.source) && identity == activeControlIdentity) {
                        stopped = (session.protocol as? Wireguard)?.managedStopAndConfirm() == true
                        if (stopped) {
                            // Preserve the event's source owner even after control authority is reset.
                            session.source.state.value = DISCONNECTED
                            activeControlIdentity = ""
                            activeManagedTicket = ""
                        }
                    }
                }
            } catch (_: Exception) { stopped = false }
            sendManaged(msg, JSONObject().put("type", "managedStopped").put("stopRequestId", request)
                .put("healthContextId", identity).put("stopped", stopped))
        }
    }

    @MainThread
    private fun managedInspect(msg: Message) {
        val request = msg.data.getString("inspectRequestId").orEmpty()
        if (request.length != 64) return
        managedStarts.invalidateAll()
        pendingVpnConfig = null
        connectionJob?.cancel()
        val session = activeSession
        val connectionToCancel = connectionJob
        mainScope.launch {
            var ownState = "unknown"
            try {
                withTimeout(3000) {
                    connectionToCancel?.cancelAndJoin()
                    if (connectionJob === connectionToCancel) connectionJob = null
                    if (!session.source.isCurrent(activeSession.source)) return@withTimeout
                    val protocol = session.protocol as? Wireguard
                    ownState = if (protocol?.managedIsBackendOff() == true || (protocol == null && isUnknown)) "off"
                        else if (activeControlIdentity.isNotBlank()) "active" else "unknown"
                }
            } catch (_: Exception) { }
            sendManaged(msg, JSONObject().put("type", "managedInspection").put("inspectRequestId", request)
                .put("state", ownState).put("controlIdentity", if (ownState == "active") activeControlIdentity else ""))
        }
    }

    @MainThread
    private fun reconnect() {
        if (managedRequired || !isConnected) return

        Log.d(TAG, "Reconnect VPN")

        protocolState.value = RECONNECTING
        val session = activeSession
        connectionJob = connectionScope.launch(connectionExceptionHandler(session)) {
            session.protocol?.reconnectVpn(Builder(), ::protect)
            (session.protocol as? Wireguard)?.let { protocol ->
                mainScope.launch { if (session.source.isCurrent(activeSession.source)) launchAwgHealthSending(protocol) }
            }
        }
    }

    /**
     * Utils methods
     */
    private fun onError(msg: String, session: ConnectionSession = activeSession) {
        Log.e(TAG, msg)
        mainScope.launch {
            if (!session.source.isCurrent(activeSession.source)) return@launch
            clientMessengers.send {
                ServiceEvent.ERROR.packToMessage {
                    putString(MSG_ERROR, msg)
                    session.source.identity.let { identity ->
                        if (identity.ticket != null && identity.context != null) {
                            putString(MSG_MANAGED_TICKET, identity.ticket)
                            putString(MSG_HEALTH_CONTEXT_ID, identity.context)
                        }
                    }
                }
            }
        }
    }

    private fun parseConfigToJson(vpnConfig: String): JSONObject? =
        if (vpnConfig.isBlank()) {
            null
        } else {
            try {
                JSONObject(vpnConfig)
            } catch (e: JSONException) {
                onError("Invalid VPN config json format: ${e.message}")
                null
            }
        }

    private fun saveServerData(config: JSONObject?) {
        serverName = config?.opt("description") as String?
        serverIndex = config?.opt("serverIndex") as Int? ?: -1
        Log.d(TAG, "Save server data: ($serverIndex, $serverName)")
        Prefs.save(PREFS_SERVER_NAME, serverName)
        Prefs.save(PREFS_SERVER_INDEX, serverIndex)
    }

    private fun loadServerData() {
        serverName = Prefs.load<String>(PREFS_SERVER_NAME).ifBlank { null }
        if (serverName != null) serverIndex = Prefs.load(PREFS_SERVER_INDEX)
        Log.d(TAG, "Load server data: ($serverIndex, $serverName)")
    }

    private fun checkPermission(): Boolean =
        if (prepare(applicationContext) != null) {
            Intent(this, VpnRequestActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_PROTOCOL, vpnProto)
            }.also {
                startActivity(it)
            }
            false
        } else {
            true
        }

    companion object {
        fun isRunning(context: Context, processName: String): Boolean =
            context.getSystemService<ActivityManager>()!!.runningAppProcesses.any {
                it.processName == processName && it.importance <= IMPORTANCE_FOREGROUND_SERVICE
            }
    }
}
