package org.amnezia.vpn

/** Tracks only the current Mayak control session and stop requests that still need an ACK. */
internal class ManagedControlBindingLifetime {
    private data class Session(val ticket: String, val context: String)
    data class StatusIdentity(val ticket: String?, val context: String?)

    private var current: Session? = null
    private var unavailable: Session? = null
    private val pendingStops = linkedMapOf<String, Session>()
    private var destroyed = false

    @Synchronized
    fun activate(ticket: String, context: String): Boolean {
        if (destroyed || ticket.isBlank() || context.isBlank()) return false
        val session = Session(ticket, context)
        if (current != null && current != session) return false
        current = session
        return true
    }

    @Synchronized
    fun failStart(ticket: String, context: String) {
        if (current == Session(ticket, context)) current = null
    }

    /** A recovery stop is allowed to reach the service even if this Activity did not start it. */
    @Synchronized
    fun retainForStop(requestId: String, context: String, ticket: String): Boolean {
        if (destroyed || requestId.isBlank() || context.isBlank() || ticket.isBlank()) return false
        val session = current
        val recovery = ticket == "recovery:$context"
        val requested = Session(ticket, context)
        if (!recovery && session != requested && unavailable != requested) return false
        val previous = pendingStops[requestId]
        if (previous != null && previous != requested) return false
        pendingStops[requestId] = requested
        return true
    }

    /** Only the exact stop request/context can release its session; stale A cannot clear B. */
    @Synchronized
    fun stopAcknowledged(requestId: String, context: String, stopped: Boolean): Boolean {
        val session = pendingStops[requestId] ?: return false
        if (session.context != context) return false
        pendingStops.remove(requestId)
        val recovery = session.ticket == "recovery:$context"
        if (stopped && current?.context == context && (recovery || current?.ticket == session.ticket)) current = null
        if (stopped && unavailable?.context == context && (recovery || unavailable?.ticket == session.ticket)) unavailable = null
        return true
    }

    @Synchronized
    fun deny(ticket: String, context: String) {
        if (current == Session(ticket, context)) current = null
    }

    /** Untagged service state can update legacy UI, but cannot end a managed owner. */
    @Synchronized
    fun acceptStatus(ticket: String?, context: String?, disconnected: Boolean): Boolean {
        if (destroyed) return false
        val active = current
        if (active != null) {
            if (ticket != active.ticket || context != active.context) return false
            if (disconnected) sessionEnded()
            return true
        }
        val pending = pendingStops.values.firstOrNull { it.ticket == ticket && it.context == context }
        if (pending != null) {
            if (disconnected) sessionEnded()
            return true
        }
        // Legacy sessions have no managed owner; preserve their status delivery.
        return ticket.isNullOrBlank() && context.isNullOrBlank() && pendingStops.isEmpty()
    }

    @Synchronized
    fun shouldRetainBinding(): Boolean = !destroyed && (current != null || pendingStops.isNotEmpty())

    @Synchronized
    fun acceptsCallbacks(): Boolean = !destroyed

    @Synchronized
    fun shouldBindOnStart(alreadyBound: Boolean, serviceRunning: Boolean): Boolean =
        !destroyed && !alreadyBound && (shouldRetainBinding() || serviceRunning)

    @Synchronized
    fun shouldUnbindForUiStop(): Boolean = !shouldRetainBinding()

    /** Real binder/service loss is fail-closed and invalidates outstanding acknowledgements. */
    @Synchronized
    fun serviceLost() {
        current?.let { unavailable = it }
        current = null
        pendingStops.clear()
    }

    /** Tunnel revocation/normal disconnect ends active ownership but preserves a stop awaiting ACK. */
    @Synchronized
    fun sessionEnded() {
        current?.let { unavailable = it }
        current = null
    }

    @Synchronized
    fun destroy() {
        serviceLost()
        unavailable = null
        destroyed = true
    }
}
