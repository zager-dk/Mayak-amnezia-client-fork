package org.amnezia.vpn

/** Synchronous request ownership shared by Qt/JNI callers and Android UI callbacks. */
internal class ManagedPermissionRequestTokens {
    private val pending = hashSetOf<String>()

    @Synchronized
    fun reserve(requestId: String): Boolean = requestId.isNotBlank() && pending.add(requestId)

    @Synchronized
    fun isCurrent(requestId: String): Boolean = requestId in pending

    @Synchronized
    fun cancel(requestId: String): Boolean = pending.remove(requestId)

    @Synchronized
    fun complete(requestId: String): Boolean = pending.remove(requestId)

    @Synchronized
    fun abandonAll(): List<String> = pending.toList().also { pending.clear() }
}

/** Serializes Android's fixed permission request codes across cancellable Mayak requests. */
internal class ManagedPermissionPreflightSerial {
    enum class ResultDisposition { Current, Cancelled, Stale }
    data class Callback(val disposition: ResultDisposition, val nextRequestId: String? = null)

    private var activeRequestId: String? = null
    private val queuedRequestIds = ArrayDeque<String>()
    private var activeCancelled = false
    private var systemResultOutstanding = false

    /** Returns true only when the caller owns the OS request slot immediately. */
    @Synchronized
    fun enqueue(requestId: String): Boolean {
        if (requestId.isBlank() || requestId == activeRequestId || requestId in queuedRequestIds) return false
        if (activeRequestId == null) {
            activeRequestId = requestId
            activeCancelled = false
            systemResultOutstanding = false
            return true
        }
        queuedRequestIds.addLast(requestId)
        return false
    }

    @Synchronized
    fun owns(requestId: String): Boolean = activeRequestId == requestId && !activeCancelled

    @Synchronized
    fun markSystemResultOutstanding(requestId: String): Boolean {
        if (!owns(requestId) || systemResultOutstanding) return false
        systemResultOutstanding = true
        return true
    }

    /**
     * Cancelling an outstanding system dialog retains its request as a tombstone.
     * A later result is consumed for that request before the queued request starts.
     */
    @Synchronized
    fun cancel(requestId: String): String? {
        if (queuedRequestIds.remove(requestId)) return null
        if (activeRequestId != requestId) return null
        activeCancelled = true
        return if (systemResultOutstanding) null else releaseActiveAndNext()
    }

    @Synchronized
    fun consumeSystemResult(requestId: String): Callback {
        if (activeRequestId != requestId || !systemResultOutstanding) return Callback(ResultDisposition.Stale)
        systemResultOutstanding = false
        if (activeCancelled) return Callback(ResultDisposition.Cancelled, releaseActiveAndNext())
        return Callback(ResultDisposition.Current)
    }

    @Synchronized
    fun finish(requestId: String): String? {
        if (activeRequestId != requestId || activeCancelled) return null
        return releaseActiveAndNext()
    }

    @Synchronized
    fun abandonAll(): List<String> {
        val abandoned = buildList {
            activeRequestId?.let(::add)
            addAll(queuedRequestIds)
        }
        activeRequestId = null
        activeCancelled = false
        systemResultOutstanding = false
        queuedRequestIds.clear()
        return abandoned
    }

    private fun releaseActiveAndNext(): String? {
        activeRequestId = null
        activeCancelled = false
        systemResultOutstanding = false
        if (queuedRequestIds.isEmpty()) return null
        return queuedRequestIds.removeFirst().also { activeRequestId = it }
    }
}
