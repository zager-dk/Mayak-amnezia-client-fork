package org.amnezia.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import org.amnezia.vpn.util.Log

private const val TAG = "MayakFailoverReceiver"
// Keeps the (otherwise cached/frozen) main process runnable while Qt stops the dead exit, then
// fetches, admits, starts and proves another one, including its connect retries (review N2).
// With a safe margin to the 60 s background-broadcast limit (an overrun would be an ANR that
// kills the process mid-failover, with the VPN already down).
private const val FAILOVER_HOLD_MS = 45_000L
// Background connect from the shade/tile (review N3): fetch, admit, start and prove.
private const val CONNECT_HOLD_MS = 30_000L

/**
 * Mayak, explicit package-local broadcasts (not exported) to the app's main process:
 * - [MayakLaunch.ACTION_FAILOVER]: the VPN service watchdog could not repair the current exit
 *   while the app UI was hidden. Hands the request to the running Qt owner, which reconnects
 *   preferring another exit. If the app is not running nothing happens: the tunnel stays as
 *   it is and the service keeps its own soft repair.
 * - [MayakLaunch.ACTION_HOLD]: a background connect was handed to Qt; keep the process
 *   runnable while it completes.
 */
class MayakFailoverReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val holdMs = when (intent.action) {
            MayakLaunch.ACTION_FAILOVER -> {
                val healthContext = intent.getStringExtra(MayakLaunch.EXTRA_HEALTH_CONTEXT).orEmpty()
                if (healthContext.isBlank()) return
                val handled = runCatching { MayakLaunch.liveFailover?.invoke(healthContext) == true }.getOrDefault(false)
                Log.i(TAG, "MayakNet event=failover_request handled=${if (handled) 1 else 0}")
                if (!handled) return
                FAILOVER_HOLD_MS
            }
            MayakLaunch.ACTION_HOLD -> if (MayakLaunch.liveConnect != null) CONNECT_HOLD_MS else return
            else -> return
        }
        val pending = goAsync()
        Handler(Looper.getMainLooper()).postDelayed({ runCatching { pending.finish() } }, holdMs)
    }
}
