package org.amnezia.vpn

import android.Manifest.permission
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationChannelCompat.Builder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationCompat.Action
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.amnezia.vpn.protocol.ProtocolState
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.TrafficStats.TrafficData

private const val TAG = "ServiceNotification"

private const val OLD_NOTIFICATION_CHANNEL_ID: String = "org.amnezia.vpn.notification"
private const val NOTIFICATION_CHANNEL_ID: String = "org.amnezia.vpn.notifications"
const val NOTIFICATION_ID = 1337
private const val DISCONNECTED_NOTIFICATION_ID = 1338

private const val GET_ACTIVITY_REQUEST_CODE = 0
private const val CONNECT_REQUEST_CODE = 1
private const val DISCONNECT_REQUEST_CODE = 2

class ServiceNotification(private val context: Context) {

    private val upDownSymbols = when (Build.BRAND) {
        "Infinix" -> '˅' to '˄'
        else -> '↓' to '↑'
    }

    private val notificationManager = NotificationManagerCompat.from(context)

    private val notificationBuilder = NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
        .setShowWhen(false)
        .setOngoing(true)
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
        .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .setContentIntent(
            PendingIntent.getActivity(
                context,
                GET_ACTIVITY_REQUEST_CODE,
                Intent(context, AmneziaActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        )

    private val zeroSpeed: String = with(TrafficData.ZERO) {
        formatSpeedString(rxString, txString)
    }

    fun buildNotification(serverName: String?, protocol: String?, state: ProtocolState): Notification {
        val speedString = if (state == CONNECTED) zeroSpeed else null

        Log.v(TAG, "Build notification: $serverName, $state")

        return notificationBuilder
            // Mayak: the lamp shows the state (lit = connected, empty window = not connected).
            .setSmallIcon(if (state == CONNECTED) R.drawable.ic_mayak_status_on else R.drawable.ic_amnezia_round)
            .setContentTitle((serverName ?: "AmneziaVPN") + (protocol?.let { " $it" } ?: ""))
            .setContentText(context.getString(state))
            .setSubText(speedString)
            .setWhen(System.currentTimeMillis())
            .clearActions()
            .apply {
                getAction(state)?.let {
                    addAction(it)
                }
            }
            .build()
    }

    private fun buildNotification(speed: TrafficData): Notification =
        notificationBuilder
            .setWhen(System.currentTimeMillis())
            .setSubText(getSpeedString(speed))
            .build()

    fun isNotificationEnabled(): Boolean {
        if (!context.isNotificationPermissionGranted()) return false
        if (!notificationManager.areNotificationsEnabled()) return false
        return notificationManager.getNotificationChannel(NOTIFICATION_CHANNEL_ID)?.let {
            it.importance != NotificationManager.IMPORTANCE_NONE
        } ?: true
    }

    @SuppressLint("MissingPermission")
    fun updateNotification(serverName: String?, protocol: String?, state: ProtocolState) {
        if (context.isNotificationPermissionGranted()) {
            Log.v(TAG, "Update notification: $serverName, $state")
            notificationManager.notify(NOTIFICATION_ID, buildNotification(serverName, protocol, state))
        }
    }

    /**
     * Mayak: after a disconnect the service stops and its foreground notification goes with it.
     * Leave an ordinary, dismissible "Disconnected · Connect" notification in its place, so the
     * shade keeps a one-tap connect until the user swipes it away. Cancelled on the next connect.
     */
    @SuppressLint("MissingPermission")
    fun showDisconnected(serverName: String?, protocol: String?) {
        if (!isNotificationEnabled()) return
        val connect = getAction(DISCONNECTED) ?: return
        val notification = NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setShowWhen(false)
            .setOngoing(false)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setSmallIcon(R.drawable.ic_amnezia_round)
            .setContentTitle((serverName ?: "AmneziaVPN") + (protocol?.let { " $it" } ?: ""))
            .setContentText(context.getString(DISCONNECTED))
            .setContentIntent(
                PendingIntent.getActivity(
                    context,
                    GET_ACTIVITY_REQUEST_CODE,
                    Intent(context, AmneziaActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )
            .addAction(connect)
            .build()
        notificationManager.notify(DISCONNECTED_NOTIFICATION_ID, notification)
    }

    fun cancelDisconnected() = notificationManager.cancel(DISCONNECTED_NOTIFICATION_ID)

    @SuppressLint("MissingPermission")
    fun updateSpeed(speed: TrafficData) {
        if (context.isNotificationPermissionGranted()) {
            notificationManager.notify(NOTIFICATION_ID, buildNotification(speed))
        }
    }

    private fun getSpeedString(traffic: TrafficData) =
        if (traffic == TrafficData.ZERO) zeroSpeed
        else formatSpeedString(traffic.rxString, traffic.txString)

    private fun formatSpeedString(rx: String, tx: String) = with(upDownSymbols) { "$first $rx  $second $tx" }

    private fun getAction(state: ProtocolState): Action? {
        return when (state) {
            CONNECTED -> {
                Action(
                    0, context.getString(R.string.disconnect),
                    PendingIntent.getBroadcast(
                        context,
                        DISCONNECT_REQUEST_CODE,
                        Intent(ACTION_DISCONNECT).apply {
                            setPackage(context.packageName)
                        },
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )
                )
            }

            DISCONNECTED -> if (MayakLaunch.isManagedConfigSaved(context)) {
                // Mayak session: only the app's Qt owner can obtain admission. The invisible
                // MayakConnectActivity hands "Connect" to a running app in the background, and
                // opens the app (then sends it back) only when it is not running.
                Action(
                    0, context.getString(R.string.connect),
                    PendingIntent.getActivity(
                        context,
                        CONNECT_REQUEST_CODE,
                        MayakLaunch.connectIntent(context),
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )
                )
            } else {
                Action(
                    0, context.getString(R.string.connect),
                    PendingIntent.getBroadcast(
                        context,
                        CONNECT_REQUEST_CODE,
                        Intent(ACTION_CONNECT).apply {
                            setPackage(context.packageName)
                        },
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )
                )
            }

            else -> null
        }
    }

    companion object {
        fun createNotificationChannel(context: Context) {
            with(NotificationManagerCompat.from(context)) {
                deleteNotificationChannel(OLD_NOTIFICATION_CHANNEL_ID)
                createNotificationChannel(
                    Builder(NOTIFICATION_CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_DEFAULT)
                        .setShowBadge(false)
                        .setSound(null, null)
                        .setVibrationEnabled(false)
                        .setLightsEnabled(false)
                        .setName("AmneziaVPN")
                        .setDescription(context.resources.getString(R.string.notificationChannelDescription))
                        .build()
                )
            }
        }
    }
}

fun Context.isNotificationPermissionGranted(): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(this, permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED
