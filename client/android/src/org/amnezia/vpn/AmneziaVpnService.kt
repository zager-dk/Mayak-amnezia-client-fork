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
// Mayak service-side watchdog (runs only while the Activity is hidden/frozen or gone).
private const val WATCHDOG_TICK_MS = 1000L
private const val WATCHDOG_RECENT_NETWORK_MS = 20_000L
private const val WATCHDOG_RX_STALE_AFTER_NETWORK_MS = 8_000L
private const val WATCHDOG_RX_STALE_MS = 20_000L
private const val WATCHDOG_HANDSHAKE_AGE_MS = 140_000L
private const val WATCHDOG_NO_HANDSHAKE_MS = 25_000L
private val WATCHDOG_BACKOFF_MS = longArrayOf(10_000L, 30_000L, 60_000L)
private const val WATCHDOG_NETWORK_LOST_EXPIRY_MS = 60_000L
private const val HIDDEN_CONNECT_HEALTH_MS = 30_000L
private const val WATCHDOG_FAILOVER_AFTER_ATTEMPTS = 2
private const val WATCHDOG_FAILOVER_REPEAT_MS = 120_000L
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
    private var recoverJob: Job? = null
    // Mayak: Activity visibility. Health/network events are streamed only to a started
    // Activity; while it is hidden (frozen) or gone the service watchdog owns recovery.
    @Volatile private var uiForeground = false
    private var watchdogJob: Job? = null
    private var underlyingLost = false
    private var underlyingLostAt = 0L
    private var underlyingValidatedAt = 0L
    // Mayak: the first seconds of a managed session need health for the owner's proof even when
    // the UI is (or goes) hidden, e.g. a background connect from the notification/tile. Bounded
    // (at most ~30 one-way messages), then health to a hidden UI pauses again.
    private var managedStartedAt = 0L
    private var backendReplacedWhileHidden = false
    private var trafficStatsUpdateJob: Job? = null
    private var awgHealthSendingJob: Job? = null
    // private var statisticsSendingJob: Job? = null
    private lateinit var networkState: NetworkState
    private lateinit var managedNetworkState: NetworkState
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
                        val replyTarget = msg.replyTo
                        // Mayak (note 12): a client process that died without UNREGISTER must not
                        // keep counting as a live, visible Activity (that would keep the watchdog off).
                        val messenger = IpcMessenger(replyTarget, clientName, onDeadObjectException = {
                            mainScope.launch {
                                clientMessengers.remove(replyTarget)?.let { dead ->
                                    Log.w(TAG, "Messenger client '${dead.name}' is dead")
                                    if (dead.name == ACTIVITY_MESSENGER_NAME && !isActivityConnected) {
                                        uiForeground = false; updateWatchdog()
                                    }
                                }
                            }
                        })
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        // Visibility follows in UI_FOREGROUND/UI_BACKGROUND; until then treat as hidden.
                        if (clientName == ACTIVITY_MESSENGER_NAME) { uiForeground = false; updateWatchdog() }
                        // if (clientName == ACTIVITY_MESSENGER_NAME && isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            // if (it.name == ACTIVITY_MESSENGER_NAME) stopSendingStatistics()
                            if (it.name == ACTIVITY_MESSENGER_NAME) setUiForeground(false, null)
                        }
                    }

                    Action.UI_BACKGROUND -> setUiForeground(false, msg.replyTo)
                    Action.UI_FOREGROUND -> setUiForeground(true, msg.replyTo)
                    Action.MANAGED_ADOPT -> managedAdopt(msg)

                    Action.CONNECT -> {
                        connect(msg.data.getString(MSG_VPN_CONFIG))
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.MANAGED_STOP -> managedStop(msg)
                    Action.MANAGED_INSPECT -> managedInspect(msg)
                    Action.MANAGED_RECOVER -> managedRecover(msg)

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
        // Mayak managed sessions: the best non-VPN (underlying) network, never our own VPN.
        managedNetworkState = NetworkState(this, ::onManagedUnderlyingValidated, ::onDefaultNetworkLost, excludeVpn = true)
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
        // Mayak: keep a dismissible "Disconnected · Connect" in the shade after the service ends.
        if (isDisconnected && MayakLaunch.isManagedConfigSaved(this)) serviceNotification.showDisconnected(serverName, vpnProto?.label)
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
                        if (managedRequired) managedNetworkState.bindNetworkListener()
                        // if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                        updateWatchdog()
                    }

                    DISCONNECTED -> {
                        networkState.unbindNetworkListener()
                        managedNetworkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        stopWatchdog()
                        // stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
                        managedNetworkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        stopWatchdog()
                        // stopSendingStatistics()
                    }

                    RECONNECTING -> {
                        stopTrafficStatsUpdateJob()
                        stopAwgHealthSending()
                        stopWatchdog()
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
                }?.takeIf { uiForeground || (managedStartedAt != 0L &&
                    android.os.SystemClock.elapsedRealtime() - managedStartedAt < HIDDEN_CONNECT_HEALTH_MS) }?.let { health ->
                    // Never stream into a stopped (frozen) Activity: see setUiForeground().
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
            MayakLaunch.markManagedConfig(this, parseConfigToJson(persisted)?.optBoolean("managedRequired") == true)
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
        stopWatchdog()
        backendReplacedWhileHidden = false
        underlyingLost = false
        underlyingValidatedAt = 0L
        managedStartedAt = if (managedTicket.isNotBlank()) android.os.SystemClock.elapsedRealtime() else 0L
        serviceNotification.cancelDisconnected()
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
        // Mayak: a managed session stopped outside the Qt owner (notification/tile "Disconnect",
        // VPN revoked). Tell the owner it was the user's stop, not a fault to recover from.
        if (managedRequired && activeControlIdentity.isNotBlank()) {
            Log.i(TAG, "MayakNet event=user_stop")
            val result = JSONObject().put("type", "managedUserStop").put("owner", "MayakVpnAwgLifecycleV1")
                .put("healthContextId", activeControlIdentity).toString()
            clientMessengers.values.filter { it.name == ACTIVITY_MESSENGER_NAME }.forEach { messenger ->
                messenger.send { ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result) } }
            }
        }
        stopWatchdog()

        protocolState.value = DISCONNECTING
        val session = activeSession
        val connectionToCancel = connectionJob
        val recoveryToFinish = recoverJob
        disconnectionJob = connectionScope.launch(connectionExceptionHandler(session)) {
            connectionToCancel?.cancelAndJoin()
            if (connectionJob === connectionToCancel) connectionJob = null
            // Mayak: a soft replacement in flight would bring a new backend up after this stop.
            recoveryToFinish?.join()

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

    // The Looper recycles a Message after dispatch: async answers keep only the reply target.
    private fun sendManaged(replyTo: Messenger?, result: JSONObject) {
        result.put("owner", "MayakVpnAwgLifecycleV1")
        replyTo?.let { target -> IpcMessenger(target).send {
            ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result.toString()) }
        } }
    }

    @MainThread
    private fun managedStop(msg: Message) {
        val request = msg.data.getString("stopRequestId").orEmpty()
        val identity = msg.data.getString("healthContextId").orEmpty()
        val ticket = msg.data.getString("managedTicket").orEmpty()
        if (request.length != 64 || identity.isBlank()) return
        val replyTo = msg.replyTo
        if (identity != activeControlIdentity || (ticket != activeManagedTicket && ticket != "recovery:" + identity)) {
            // Mayak: a fresh service instance (e.g. after a system-UI disconnect ended the old one)
            // runs no backend at all, so the asked context is definitely down. If anything else
            // runs, the answer stays "not stopped".
            val nothingRuns = activeControlIdentity.isBlank() && (isUnknown || isDisconnected) &&
                (activeSession.protocol as? Wireguard)?.managedIsBackendOff() != false &&
                connectionJob?.isActive != true && recoverJob?.isActive != true
            if (nothingRuns) Log.i(TAG, "MayakNet event=stop_nothing_running")
            sendManaged(replyTo, JSONObject().put("type", "managedStopped").put("stopRequestId", request)
                .put("healthContextId", identity).put("stopped", nothingRuns))
            return
        }
        managedStarts.invalidateAll()
        pendingVpnConfig = null
        connectionJob?.cancel()
        stopAwgHealthSending()
        stopWatchdog()
        backendReplacedWhileHidden = false
        val session = activeSession
        val connectionToCancel = connectionJob
        val previousDisconnection = disconnectionJob
        val recoveryToFinish = recoverJob
        mainScope.launch {
            var stopped = false
            try {
                withTimeout(3000) {
                    connectionToCancel?.cancelAndJoin()
                    if (connectionJob === connectionToCancel) connectionJob = null
                    previousDisconnection?.join()
                    recoveryToFinish?.join() // never stop a backend while it is being replaced
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
            sendManaged(replyTo, JSONObject().put("type", "managedStopped").put("stopRequestId", request)
                .put("healthContextId", identity).put("stopped", stopped))
        }
    }

    @MainThread
    private fun managedInspect(msg: Message) {
        val request = msg.data.getString("inspectRequestId").orEmpty()
        if (request.length != 64) return
        val replyTo = msg.replyTo
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
            sendManaged(replyTo, JSONObject().put("type", "managedInspection").put("inspectRequestId", request)
                .put("state", ownState).put("controlIdentity", if (ownState == "active") activeControlIdentity else ""))
        }
    }

    /**
     * Mayak managed soft recovery: replace the AWG backend (new UDP socket/source port)
     * under the same managed ticket and proof context. No admission, no VPN teardown.
     */
    @MainThread
    private fun managedRecover(msg: Message) {
        val request = msg.data.getString("recoverRequestId").orEmpty()
        val identity = msg.data.getString("healthContextId").orEmpty()
        val ticket = msg.data.getString("managedTicket").orEmpty()
        if (request.length != 64 || identity.isBlank()) return
        val session = activeSession
        val protocol = session.protocol as? Wireguard
        // The Looper recycles msg after dispatch; keep the reply target for the async answer.
        val replyTo = msg.replyTo
        fun reply(recovered: Boolean) {
            val result = JSONObject().put("type", "managedRecovered").put("owner", "MayakVpnAwgLifecycleV1")
                .put("recoverRequestId", request).put("healthContextId", identity).put("recovered", recovered)
            replyTo?.let { target -> IpcMessenger(target).send {
                ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result.toString()) }
            } }
        }
        if (!managedRequired || identity != activeControlIdentity || ticket.isBlank() || ticket != activeManagedTicket ||
            protocol == null || !session.source.isCurrent(activeSession.source) ||
            !replaceManagedBackend("qt") { ok -> reply(ok) }) {
            Log.i(TAG, "MayakNet event=recover_rejected")
            reply(false)
        }
    }

    /**
     * Mayak adoption: a cold-started Qt owner proves it owns the running managed backend by
     * presenting the exact control identity AND ticket (its persisted attempt id). Nothing is
     * revealed to the caller. On a match the backend gets the same soft replacement as a
     * recovery (new socket, same TUN/context), so the owner's normal tunnel proof sees a fresh
     * handshake. Any mismatch is a plain refusal; the owner then stops it the old way.
     */
    @MainThread
    private fun managedAdopt(msg: Message) {
        val request = msg.data.getString("adoptRequestId").orEmpty()
        val identity = msg.data.getString("healthContextId").orEmpty()
        val ticket = msg.data.getString("managedTicket").orEmpty()
        if (request.length != 64 || identity.isBlank()) return
        val replyTo = msg.replyTo // the Looper recycles msg after dispatch
        fun reply(adopted: Boolean) {
            val result = JSONObject().put("type", "managedAdopted").put("owner", "MayakVpnAwgLifecycleV1")
                .put("adoptRequestId", request).put("healthContextId", identity).put("adopted", adopted)
            replyTo?.let { target -> IpcMessenger(target).send {
                ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result.toString()) }
            } }
        }
        // The running backend is handed over as is: a replacement (new socket) loses its first
        // handshake and costs seconds; the owner proves the live session through the tunnel.
        val protocol = activeSession.protocol as? Wireguard
        if (!managedRequired || identity != activeControlIdentity || ticket.isBlank() || ticket != activeManagedTicket ||
            protocol == null || !isConnected || protocol.managedIsBackendOff() ||
            connectionJob?.isActive == true || disconnectionJob?.isActive == true || recoverJob?.isActive == true) {
            Log.i(TAG, "MayakNet event=adopt_rejected")
            reply(false)
            return
        }
        backendReplacedWhileHidden = false
        Log.i(TAG, "MayakNet event=adopt_handover")
        reply(true)
    }

    /**
     * Shared soft replacement core (Qt request or service watchdog): new AWG backend, same
     * managed ticket and proof context. Returns false when not allowed right now.
     */
    @MainThread
    private fun replaceManagedBackend(origin: String, onDone: (Boolean) -> Unit): Boolean {
        val identity = activeControlIdentity
        val session = activeSession
        val protocol = session.protocol as? Wireguard
        if (!managedRequired || identity.isBlank() || activeManagedTicket.isBlank() || protocol == null || !isConnected ||
            connectionJob?.isActive == true || disconnectionJob?.isActive == true || recoverJob?.isActive == true) return false
        Log.i(TAG, "MayakNet event=recover_start origin=$origin")
        // The backend generation changes now; a hidden Qt owner learns it via managedResume.
        if (!(uiForeground && isActivityConnected)) backendReplacedWhileHidden = true
        val startedAt = android.os.SystemClock.elapsedRealtime()
        recoverJob = connectionScope.launch {
            val replaced = protocol.managedRecover(Builder(), ::protect, identity)
            mainScope.launch {
                val current = session.source.isCurrent(activeSession.source) && identity == activeControlIdentity
                val ok = replaced && current
                Log.i(TAG, "MayakNet event=${if (ok) "recover_applied" else "recover_failed"} origin=$origin " +
                    "elapsed_ms=${android.os.SystemClock.elapsedRealtime() - startedAt}")
                onDone(ok)
            }
        }
        return true
    }

    /**
     * Activity visibility. Android freezes a stopped Activity's process; one-way health
     * messages into it exhaust its async binder space and the system kills the UI. So health
     * and network events go only to a started Activity, and on return it first receives a
     * managedResume summary (was the backend replaced meanwhile, is the network up).
     */
    @MainThread
    private fun setUiForeground(foreground: Boolean, replyTo: Messenger?) {
        if (foreground) {
            val messenger = replyTo?.let { clientMessengers[it] } ?: return
            if (messenger.name != ACTIVITY_MESSENGER_NAME) return
            uiForeground = true
            val identity = activeControlIdentity
            if (managedRequired && isConnected && identity.isNotBlank()) {
                val result = JSONObject().put("type", "managedResume").put("owner", "MayakVpnAwgLifecycleV1")
                    .put("healthContextId", identity).put("backendReplaced", backendReplacedWhileHidden)
                    .put("networkAvailable", !underlyingLost).toString()
                messenger.send { ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result) } }
                Log.i(TAG, "MayakNet event=ui_resume replaced=${if (backendReplacedWhileHidden) 1 else 0} " +
                    "no_network=${if (underlyingLost) 1 else 0}")
            }
            backendReplacedWhileHidden = false
        } else if (uiForeground) {
            // Only the Activity's own messenger may report the UI hidden (note 12).
            if (replyTo?.let { clientMessengers[it] }?.name != ACTIVITY_MESSENGER_NAME) return
            uiForeground = false
            Log.i(TAG, "MayakNet event=ui_hidden")
        }
        updateWatchdog()
    }

    @MainThread
    private fun updateWatchdog() {
        val wanted = managedRequired && isConnected && !(uiForeground && isActivityConnected)
        if (!wanted) { stopWatchdog(); return }
        if (watchdogJob?.isActive == true) return
        val session = activeSession
        val protocol = session.protocol as? Wireguard ?: return
        watchdogJob = mainScope.launch { runWatchdog(session, protocol) }
    }

    @MainThread
    private fun stopWatchdog() {
        watchdogJob?.cancel()
        watchdogJob = null
    }

    /**
     * Stuck-tunnel watchdog while no live Qt owner can act (UI hidden/frozen or killed).
     * Same signals as the Qt ladder, from own-peer telemetry only (no addresses, no traffic
     * content): the device keeps sending but nothing comes back and the handshake is stale,
     * or right after a network change RX stays flat. Bounded: 0 / 10 / 30 s, then 60 s.
     */
    private suspend fun runWatchdog(session: ConnectionSession, protocol: Wireguard) {
        Log.i(TAG, "MayakNet event=watchdog_on")
        var generation = Long.MIN_VALUE
        var lastRx = -1L
        var rxChangedAt = 0L
        var txAtRxChange = 0L
        var invalidSince = 0L
        var attempts = 0
        var nextAt = 0L
        var failoverAt = 0L
        try {
            while (true) {
                delay(WATCHDOG_TICK_MS)
                if (!session.source.isCurrent(activeSession.source) || !managedRequired || !isConnected) break
                if (uiForeground && isActivityConnected) break
                val now = android.os.SystemClock.elapsedRealtime()
                val sample = protocol.tunnelHealth.value?.takeIf { protocol.isCurrentTunnelHealth(it) }
                val health = sample?.takeIf { it.valid }
                var stuck = false
                var reason = ""
                if (health == null) {
                    // A replaced backend that never completes a handshake reports no valid health.
                    if (invalidSince == 0L) invalidSince = now
                    if (now - invalidSince >= WATCHDOG_NO_HANDSHAKE_MS) { stuck = true; reason = "no_handshake" }
                } else {
                    invalidSince = 0L
                    if (health.generation != generation || health.rxTotal < lastRx) {
                        generation = health.generation; lastRx = health.rxTotal
                        rxChangedAt = now; txAtRxChange = health.txTotal
                        continue
                    }
                    if (health.rxTotal > lastRx) {
                        lastRx = health.rxTotal; rxChangedAt = now; txAtRxChange = health.txTotal
                        attempts = 0; nextAt = 0L
                        continue
                    }
                    val recentNetwork = underlyingValidatedAt != 0L && now - underlyingValidatedAt < WATCHDOG_RECENT_NETWORK_MS
                    val rxStale = now - rxChangedAt
                    val txGrew = health.txTotal > txAtRxChange
                    val handshakeAge = System.currentTimeMillis() - health.latestHandshakeEpochMs
                    stuck = txGrew && if (recentNetwork) rxStale >= WATCHDOG_RX_STALE_AFTER_NETWORK_MS
                        else rxStale >= WATCHDOG_RX_STALE_MS && handshakeAge >= WATCHDOG_HANDSHAKE_AGE_MS
                    if (stuck) reason = if (recentNetwork) "rx_flat_after_network" else "handshake_stale"
                }
                // A loss without a later VALIDATED (captive checks often fail in RU) expires,
                // like the Qt owner's network-lost window: never disable repair for the session.
                val lost = underlyingLost && now - underlyingLostAt < WATCHDOG_NETWORK_LOST_EXPIRY_MS
                if (!stuck || lost || now < nextAt) continue
                // Mayak failover: new sockets to this exit did not help, the network is up, so the
                // exit itself is unreachable. Wake the Qt owner to reconnect, another exit first.
                if (attempts >= WATCHDOG_FAILOVER_AFTER_ATTEMPTS && now >= failoverAt && requestOwnerFailover()) {
                    failoverAt = now + WATCHDOG_FAILOVER_REPEAT_MS
                    nextAt = now + WATCHDOG_BACKOFF_MS.last()
                    Log.i(TAG, "MayakNet event=watchdog_failover reason=$reason attempts=$attempts")
                    continue
                }
                val delayMs = WATCHDOG_BACKOFF_MS[minOf(attempts, WATCHDOG_BACKOFF_MS.size - 1)]
                if (!replaceManagedBackend("watchdog") { ok ->
                        Log.i(TAG, "MayakNet event=watchdog_result ok=${if (ok) 1 else 0} attempt=$attempts")
                    }) continue
                attempts++
                nextAt = now + delayMs
                invalidSince = 0L
                Log.i(TAG, "MayakNet event=watchdog_stuck reason=$reason attempt=$attempts next_s=${delayMs / 1000}")
            }
        } finally {
            Log.i(TAG, "MayakNet event=watchdog_off")
        }
    }

    /**
     * Explicit, package-local broadcast to [MayakFailoverReceiver] in the app's main process. A
     * broadcast is delivered even to a cached (frozen) process; the receiver hands the request
     * to a running Qt owner and keeps the process runnable while it switches exits. Carries only
     * the random health-context id.
     */
    @MainThread
    private fun requestOwnerFailover(): Boolean {
        val identity = activeControlIdentity
        // Review N6: only a live owner (its Activity messenger still registered) can switch
        // exits; never start the app process just to find nobody there.
        if (!managedRequired || identity.isBlank() || !isActivityConnected) return false
        Log.i(TAG, "MayakNet event=failover_request")
        sendBroadcast(Intent(this, MayakFailoverReceiver::class.java)
            .setAction(MayakLaunch.ACTION_FAILOVER)
            .putExtra(MayakLaunch.EXTRA_HEALTH_CONTEXT, identity))
        return true
    }

    // Underlying network events for the Mayak managed owner. No addresses or network ids.
    @MainThread
    private fun notifyManagedNetwork(state: String) {
        val identity = activeControlIdentity
        if (!managedRequired || identity.isBlank()) return
        Log.i(TAG, "MayakNet event=$state")
        // A hidden (frozen) Activity gets the current network state in managedResume instead.
        if (!uiForeground) return
        val result = JSONObject().put("type", "managedNetwork").put("owner", "MayakVpnAwgLifecycleV1")
            .put("healthContextId", identity).put("state", state).toString()
        clientMessengers.values.filter { it.name == ACTIVITY_MESSENGER_NAME }.forEach { messenger ->
            messenger.send { ServiceEvent.MANAGED_RESULT.packToMessage { putString(MSG_MANAGED_RESULT, result) } }
        }
    }

    @MainThread
    private fun onDefaultNetworkLost() {
        underlyingLost = true
        underlyingLostAt = android.os.SystemClock.elapsedRealtime()
        if (managedRequired && isConnected) notifyManagedNetwork("network_lost")
    }

    // Managed sessions never restart (no new admission) autonomously; the Qt owner decides,
    // and while it is hidden the watchdog may only do the same soft backend replacement.
    @MainThread
    private fun onManagedUnderlyingValidated() {
        underlyingLost = false
        underlyingValidatedAt = android.os.SystemClock.elapsedRealtime()
        if (managedRequired && isConnected) notifyManagedNetwork("network_validated")
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
