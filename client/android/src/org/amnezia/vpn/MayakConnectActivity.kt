package org.amnezia.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import org.amnezia.vpn.util.Log

private const val TAG = "MayakConnectActivity"

/**
 * Mayak: invisible trampoline for the tile / notification "Connect" (Theme.NoDisplay, not
 * exported, no history). Android forbids starting activities from receivers/services opened by a
 * notification, so the entry point itself is an Activity. It never shows UI itself:
 * - a running app gets the request in the background, and the main process is kept runnable
 *   for the connect (review N3);
 * - if VPN consent is needed (it can only be given in a visible app), the app is opened;
 * - otherwise the app is started and sends itself back once the request is handed over.
 */
class MayakConnectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null && intent?.action == MayakLaunch.ACTION_CONNECT) {
            val needsConsent = runCatching { VpnService.prepare(this) != null }.getOrDefault(true)
            val handled = !needsConsent && runCatching { MayakLaunch.liveConnect?.invoke() == true }.getOrDefault(false)
            Log.i(TAG, "MayakNet event=connect_request source=system_ui background=${if (handled) 1 else 0} " +
                "consent=${if (needsConsent) 1 else 0}")
            when {
                handled -> sendBroadcast(Intent(this, MayakFailoverReceiver::class.java).setAction(MayakLaunch.ACTION_HOLD))
                else -> startActivity(MayakLaunch.appConnectIntent(this, background = !needsConsent))
            }
        }
        finish()
        overridePendingTransition(0, 0)
    }
}
