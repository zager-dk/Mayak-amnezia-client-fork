package org.amnezia.vpn

import kotlinx.coroutines.flow.MutableStateFlow

/** A protocol instance is initialized once with this source and never rebound to another owner. */
internal class ManagedProtocolState<S>(ticket: String, context: String, initialState: S) {
    val state = MutableStateFlow(initialState)
    val identity = if (ticket.isNotBlank() && context.isNotBlank())
        ManagedControlBindingLifetime.StatusIdentity(ticket, context)
    else ManagedControlBindingLifetime.StatusIdentity(null, null)

    /** Source identity, never state equality, decides whether queued work still owns the service. */
    fun isCurrent(current: ManagedProtocolState<S>): Boolean = this === current
}
