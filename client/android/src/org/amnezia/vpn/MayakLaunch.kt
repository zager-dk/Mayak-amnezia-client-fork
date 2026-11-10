package org.amnezia.vpn

import android.content.Context
import android.content.Intent
import org.amnezia.vpn.util.Prefs
import org.json.JSONObject

/**
 * Mayak: system-UI entry points (quick-settings tile, notification "Connect").
 *
 * A Mayak (managed) session needs fresh admission that only the app's Qt owner can obtain,
 * so the VPN service cannot start one from a saved config. For a Mayak config these entry
 * points open the invisible [MayakConnectActivity]: it hands the request to an already running
 * app in the background ([liveConnect]), or starts the app with [EXTRA_CONNECT] +
 * [EXTRA_BACKGROUND] (the app connects and moves itself back). Plain (non-Mayak) configs keep
 * the original service-side behaviour.
 */
object MayakLaunch {
    const val EXTRA_CONNECT = "ru.mayaklight.vpn.extra.MAYAK_CONNECT"
    const val EXTRA_BACKGROUND = "ru.mayaklight.vpn.extra.MAYAK_BACKGROUND"
    // Distinct action: PendingIntent identity ignores extras, so a plain "open app" PendingIntent
    // with the same component and request code must never be reused for (or by) this one.
    const val ACTION_CONNECT = "ru.mayaklight.vpn.action.MAYAK_CONNECT"
    private const val PREFS_CONFIG_KEY = "LAST_CONF" // = AmneziaVpnService persisted config

    /**
     * Set by the running app (main process) once its Qt owner is ready, cleared when it goes.
     * Returns true when the connect request was handed to Qt.
     */
    @Volatile var liveConnect: (() -> Boolean)? = null

    // Service watchdog -> main process: the current exit is unreachable, reconnect elsewhere.
    const val ACTION_FAILOVER = "ru.mayaklight.vpn.action.MAYAK_FAILOVER"
    const val EXTRA_HEALTH_CONTEXT = "ru.mayaklight.vpn.extra.HEALTH_CONTEXT"

    /** Set by the running app once Qt is ready; true when the failover request reached Qt. */
    @Volatile var liveFailover: ((String) -> Boolean)? = null

    // Plain one-byte marker ("1"/"0", no secret) next to the encrypted config. Unlike the
    // per-process SharedPreferences cache it is re-read on every call, so the tile process
    // never acts on a stale config type (note 13).
    private const val MANAGED_MARKER = "mayak_managed_config"

    // Mayak Xray path: "1" while a managed Xray session may run in XrayService (written by the
    // service process, read by a cold-started app to inspect the right service).
    private const val MANAGED_XRAY_MARKER = "mayak_managed_xray"

    fun markManagedXray(context: Context, active: Boolean) {
        runCatching { java.io.File(context.noBackupFilesDir, MANAGED_XRAY_MARKER).writeText(if (active) "1" else "0") }
    }

    fun isManagedXrayActive(context: Context): Boolean =
        runCatching { java.io.File(context.noBackupFilesDir, MANAGED_XRAY_MARKER).readText().trim() == "1" }.getOrDefault(false)

    fun markManagedConfig(context: Context, managed: Boolean) {
        runCatching { java.io.File(context.noBackupFilesDir, MANAGED_MARKER).writeText(if (managed) "1" else "0") }
    }

    /** The last saved config is a Mayak session (persisted with managedRequired=true). */
    fun isManagedConfigSaved(context: Context? = null): Boolean {
        context?.let { ctx ->
            runCatching { java.io.File(ctx.noBackupFilesDir, MANAGED_MARKER).readText().trim() }.getOrNull()
                ?.let { return it == "1" }
        }
        return runCatching {
            JSONObject(Prefs.load<String>(PREFS_CONFIG_KEY)).optBoolean("managedRequired")
        }.getOrDefault(false)
    }

    /** Entry for the tile and the notification: the invisible connect trampoline. */
    fun connectIntent(context: Context): Intent =
        Intent(context, MayakConnectActivity::class.java)
            .setAction(ACTION_CONNECT)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)

    // Review N4: AmneziaActivity is exported (launcher). A connect request is accepted only with
    // this per-process random token, which only our non-exported trampoline (same process) has.
    const val EXTRA_TOKEN = "ru.mayaklight.vpn.extra.MAYAK_TOKEN"
    val launchToken: String by lazy { java.util.UUID.randomUUID().toString() }

    // Trampoline -> MayakFailoverReceiver: keep the main process runnable during a background connect.
    const val ACTION_HOLD = "ru.mayaklight.vpn.action.MAYAK_HOLD"

    /** Starts the app itself to connect; with [background] it returns to the back afterwards. */
    fun appConnectIntent(context: Context, background: Boolean): Intent =
        Intent(context, AmneziaActivity::class.java)
            .setAction(ACTION_CONNECT)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(EXTRA_CONNECT, true)
            .putExtra(EXTRA_BACKGROUND, background)
            .putExtra(EXTRA_TOKEN, launchToken)
}
