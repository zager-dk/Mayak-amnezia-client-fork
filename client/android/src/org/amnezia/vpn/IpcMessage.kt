package org.amnezia.vpn

import android.os.Bundle
import android.os.Message
import kotlin.enums.enumEntries

sealed interface IpcMessage {
    companion object {
        @OptIn(ExperimentalStdlibApi::class)
        inline fun <reified T> extractFromMessage(msg: Message): T
            where T : Enum<T>,
                  T : IpcMessage {
            val values = enumEntries<T>()
            if (msg.what !in values.indices) {
                throw IllegalArgumentException("IPC action or event not found for the message: $msg")
            }
            return values[msg.what]
        }
    }
}

enum class ServiceEvent : IpcMessage {
    STATUS_CHANGED,
    STATUS,
    STATISTICS_UPDATE,
    ERROR,
    AWG_HEALTH_UPDATE,
    MANAGED_RESULT
}

enum class Action : IpcMessage {
    REGISTER_CLIENT,
    UNREGISTER_CLIENT,
    CONNECT,
    DISCONNECT,
    REQUEST_STATUS,
    NOTIFICATION_PERMISSION_GRANTED,
    SET_SAVE_LOGS,
    MANAGED_STOP,
    MANAGED_INSPECT,
    MANAGED_RECOVER,
    // Mayak: the Activity's visibility. A stopped Activity is frozen by Android, so the
    // service must not stream health into it and owns stuck-tunnel recovery meanwhile.
    UI_BACKGROUND,
    UI_FOREGROUND,
    // Mayak: a cold-started Qt owner adopts the running managed backend (proves the exact
    // control identity + ticket), followed by the same soft backend replacement.
    MANAGED_ADOPT
}

fun <T> T.packToMessage(): Message
    where T : Enum<T>, T : IpcMessage = Message.obtain().also { it.what = ordinal }

fun <T> T.packToMessage(block: Bundle.() -> Unit): Message
    where T : Enum<T>, T : IpcMessage = packToMessage().also { it.data = Bundle().apply(block) }

inline fun <reified T> Message.extractIpcMessage(): T
    where T : Enum<T>, T : IpcMessage = IpcMessage.extractFromMessage<T>(this)
