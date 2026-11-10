package org.amnezia.vpn.protocol.xray

import android.content.Context
import java.io.File
import go.Seq
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.util.Log

private const val TAG = "MayakXrayRace"
private const val RACE_CONFIG = "mayak-race.json"
private const val RACE_MAX_MEMORY: Long = 50 shl 20

/**
 * Mayak 5.1.0.21: the Xray path race engine. Runs in the app process (no VpnService, no VPN
 * interface, no route change): one xray instance with one password-protected loopback SOCKS
 * entry per path. The app probes through each entry in parallel; the result only orders the
 * paths, it is never a connection proof. Started and stopped by the Qt owner over JNI.
 */
object MayakXrayRace {
    @Volatile private var running = false

    @JvmStatic
    @Synchronized
    fun start(context: Context, configJson: String): Boolean {
        if (running) return false
        return try {
            Seq.setContext(context.applicationContext)
            val assetsPath = context.getDir("assets", Context.MODE_PRIVATE).absolutePath
            LibXray.initXray(assetsPath)
            val geoDir = File(assetsPath, "geo").absolutePath
            val configFile = File(context.cacheDir, RACE_CONFIG)
            configFile.writeText(configJson)
            val error = LibXray.runXray(geoDir, configFile.absolutePath, RACE_MAX_MEMORY)
            if (!error.isNullOrBlank()) {
                Log.w(TAG, "MayakNet event=race_engine_error")
                configFile.delete()
                false
            } else {
                running = true
                true
            }
        } catch (e: Throwable) {
            Log.w(TAG, "MayakNet event=race_engine_exception type=${e.javaClass.simpleName}")
            false
        }
    }

    @JvmStatic
    @Synchronized
    fun stop(context: Context): Boolean {
        if (!running) return true
        val error = try { LibXray.stopXray() } catch (e: Throwable) { e.javaClass.simpleName }
        running = false
        File(context.cacheDir, RACE_CONFIG).delete()
        return error.isNullOrBlank()
    }
}
