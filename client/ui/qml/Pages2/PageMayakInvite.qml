import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Style 1.0
import "../Controls2"
import "../Controls2/TextTypes"

PageType {
    id: root
    objectName: "mayak-auth-page"

    property var inviteController: typeof MayakInviteController === "undefined" ? null : MayakInviteController
    property var pageController: typeof PageController === "undefined" ? null : PageController
    property bool inviteMode: false
    property bool sawBusy: false
    property bool suppressMessage: false
    property string emailValue: ""
    property string passwordValue: ""
    property string inviteValue: ""
    readonly property bool canBindCredentials: inviteController.hasSession && inviteController.accountMetadataKnown
                                                   && !inviteController.accountHasPassword

    initialFocusItem: !inviteController.hasSession || canBindCredentials ? emailField.textField : retryButton

    function clearPassword() {
        passwordValue = ""
        passwordField.textField.clear()
        passwordField.passwordRevealed = false
    }

    function clearFields() {
        suppressMessage = false
        emailValue = ""
        emailField.textField.clear()
        clearPassword()
        inviteValue = ""
        inviteField.textField.clear()
        inviteMode = false
        flickable.contentY = 0
    }

    function leavePage() {
        if (inviteController && inviteController.busy) {
            inviteController.cancelPendingRequests()
        }
        clearFields()
    }

    function keepItemVisible(field) {
        Qt.callLater(function() {
            if (!field || !field.visible) return
            const position = field.mapToItem(flickable.contentItem, 0, 0)
            const top = position.y
            const bottom = top + field.height + 20
            if (bottom > flickable.contentY + flickable.height) {
                flickable.contentY = Math.min(flickable.contentHeight - flickable.height,
                                              bottom - flickable.height)
            } else if (top < flickable.contentY) {
                flickable.contentY = top
            }
        })
    }

    Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Escape || event.key === Qt.Key_Back) {
            root.leavePage()
            root.pageController.closePage()
            event.accepted = true
        }
    }

    StackView.onDeactivated: root.leavePage()
    StackView.onActivated: root.inviteController.refreshAccount()

    FlickableType {
        id: flickable
        objectName: "mayak-auth-scroll"
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        contentWidth: width
        contentHeight: contentColumn.implicitHeight + 24
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: contentColumn
            width: Math.min(flickable.width, 560)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 20

            Item { Layout.preferredHeight: 4 }

            NavigationBarType {
                Layout.fillWidth: true
                title: qsTr("Подключить Маяк")
                description: root.inviteController.hasSession
                             ? qsTr("Настройки аккаунта")
                             : qsTr("Вход по адресу почты")
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                implicitHeight: summary.implicitHeight + 32
                radius: 18
                color: AmneziaStyle.color.bgSurface
                border.width: 1
                border.color: AmneziaStyle.color.borderFaint

                ColumnLayout {
                    id: summary
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16
                    spacing: 6

                    H2TextType {
                        Layout.fillWidth: true
                        text: root.inviteController.hasSession
                              ? qsTr("Аккаунт Маяка")
                              : (root.inviteMode ? qsTr("Есть приглашение?") : qsTr("Рады видеть вас"))
                        color: AmneziaStyle.color.textPrimary
                    }
                    BodyTextType {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: {
                            if (!root.inviteController.hasSession) {
                                return root.inviteMode
                                        ? qsTr("Вставьте ссылку из сообщения администратора и задайте пароль для будущих входов.")
                                        : qsTr("Войдите в аккаунт, чтобы продолжить настройку на этом устройстве.")
                            }
                            if (!root.inviteController.accountMetadataKnown) {
                                return root.inviteController.busy
                                        ? qsTr("Проверяем аккаунт.")
                                        : qsTr("Не удалось проверить аккаунт. Повторите проверку или выйдите.")
                            }
                            if (root.inviteController.accountHasPassword) {
                                return root.inviteController.accountEmail.length > 0
                                        ? qsTr("Вы вошли как %1. Повторная привязка не нужна.").arg(root.inviteController.accountEmail)
                                        : qsTr("Вы вошли в аккаунт. Повторная привязка не нужна.")
                            }
                            return qsTr("Добавьте почту и пароль, чтобы входить без нового приглашения.")
                        }
                        color: AmneziaStyle.color.textSecondary
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                spacing: 8
                visible: !root.inviteController.hasSession

                ButtonType {
                    objectName: "mayak-auth-mode-login"
                    Layout.fillWidth: true
                    text: qsTr("Войти")
                    variant: root.inviteMode ? ButtonType.Secondary : ButtonType.Primary
                    enabled: !root.inviteController.busy
                    onClicked: {
                        root.inviteMode = false
                        root.suppressMessage = true
                    }
                }
                ButtonType {
                    objectName: "mayak-auth-mode-register"
                    Layout.fillWidth: true
                    text: qsTr("У меня есть приглашение")
                    variant: root.inviteMode ? ButtonType.Primary : ButtonType.Secondary
                    enabled: !root.inviteController.busy
                    onClicked: {
                        root.inviteMode = true
                        root.suppressMessage = true
                    }
                }
            }

            TextFieldType {
                id: emailField
                objectName: "mayak-auth-email-field"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: !root.inviteController.hasSession || root.canBindCredentials
                enabled: !root.inviteController.busy
                headerText: qsTr("Адрес почты")
                placeholderText: qsTr("name@example.org")
                textField.objectName: "auth-email"
                textField.text: root.emailValue
                textField.inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhEmailCharactersOnly
                textField.selectByMouse: true
                textField.Accessible.name: qsTr("Адрес почты")
                textField.onAccepted: {
                    if (root.inviteController.hasSession && !root.inviteMode) passwordField.textField.forceActiveFocus()
                    else if (root.inviteMode) inviteField.textField.forceActiveFocus()
                    else passwordField.textField.forceActiveFocus()
                }
                textField.onActiveFocusChanged: if (textField.activeFocus) root.keepItemVisible(emailField)
                Connections {
                    target: emailField.textField
                    function onTextChanged() { root.emailValue = emailField.textField.text }
                }
            }

            TextFieldType {
                id: inviteField
                objectName: "mayak-auth-invite-field"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: !root.inviteController.hasSession && root.inviteMode
                enabled: !root.inviteController.busy
                headerText: qsTr("Ссылка-приглашение")
                placeholderText: qsTr("https://mayaklight.ru/my/?invite=…")
                helperText: qsTr("Можно вставить всю ссылку или только код.")
                textField.text: root.inviteValue
                textField.objectName: "auth-invite"
                textField.selectByMouse: true
                textField.Accessible.name: qsTr("Ссылка-приглашение")
                textField.onAccepted: passwordField.textField.forceActiveFocus()
                textField.onActiveFocusChanged: if (textField.activeFocus) root.keepItemVisible(inviteField)
                Connections {
                    target: inviteField.textField
                    function onTextChanged() { root.inviteValue = inviteField.textField.text }
                }
            }

            TextFieldType {
                id: passwordField
                objectName: "mayak-auth-password-field"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: !root.inviteController.hasSession || root.canBindCredentials
                enabled: !root.inviteController.busy
                headerText: root.inviteController.hasSession
                            ? qsTr("Создайте пароль")
                            : (root.inviteMode ? qsTr("Создайте пароль") : qsTr("Пароль"))
                placeholderText: qsTr("Не менее 12 символов")
                helperText: root.inviteController.hasSession
                            ? qsTr("После привязки можно будет входить по адресу почты и паролю.")
                            : qsTr("Пароль можно вставить из менеджера паролей. Он не сохраняется в приложении.")
                passwordToggle: true
                textField.text: root.passwordValue
                textField.objectName: "auth-password"
                textField.selectByMouse: true
                textField.inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                textField.passwordMaskDelay: 0
                textField.Accessible.name: headerText
                textField.onAccepted: root.submit()
                textField.onActiveFocusChanged: if (textField.activeFocus) root.keepItemVisible(passwordField)
                Connections {
                    target: passwordField.textField
                    function onTextChanged() { root.passwordValue = passwordField.textField.text }
                }
            }

            BodyTextType {
                objectName: "mayak-auth-message"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                wrapMode: Text.WordWrap
                visible: text.length > 0
                text: root.suppressMessage ? "" : root.inviteController.message
                color: AmneziaStyle.color.textSecondary
                Accessible.name: text
            }

            // Лимит устройств: человек сам выбирает, какое устройство заменить этим.
            Rectangle {
                objectName: "mayak-auth-device-limit"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: root.inviteController.hasSession && root.inviteController.limitDevices.length > 0
                implicitHeight: limitColumn.implicitHeight + 32
                radius: 18
                color: AmneziaStyle.color.bgSurface
                border.width: 1
                border.color: AmneziaStyle.color.borderFaint

                ColumnLayout {
                    id: limitColumn
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16
                    spacing: 12

                    H2TextType {
                        Layout.fillWidth: true
                        text: qsTr("Какое устройство заменить?")
                        color: AmneziaStyle.color.textPrimary
                    }

                    Repeater {
                        model: root.inviteController.limitDevices
                        delegate: RowLayout {
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: 12

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                BodyTextType {
                                    Layout.fillWidth: true
                                    text: modelData.name + (modelData.os ? " · " + modelData.os : "")
                                    textFormat: Text.PlainText
                                    color: AmneziaStyle.color.textPrimary
                                    elide: Text.ElideRight
                                }
                                BodyTextType {
                                    Layout.fillWidth: true
                                    text: qsTr("Последний раз в сети: %1").arg(root.formatSeen(modelData.lastSeen))
                                    color: AmneziaStyle.color.textSecondary
                                }
                            }
                            ButtonType {
                                objectName: "mayak-auth-replace-device"
                                text: qsTr("Заменить")
                                variant: ButtonType.Secondary
                                enabled: !root.inviteController.busy
                                onClicked: root.inviteController.replaceDevice(modelData.id)
                            }
                        }
                    }

                    BodyTextType {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: qsTr("Заменённое устройство отключится от Маяка. Места устройств, не подключавшихся 30 дней, освобождаются сами.")
                        color: AmneziaStyle.color.textSecondary
                    }
                }
            }

            ButtonType {
                objectName: "mayak-auth-submit"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                enabled: !root.inviteController.busy
                loading: root.inviteController.busy
                text: root.inviteController.busy
                      ? qsTr("Подождите…")
                      : (root.inviteController.hasSession
                         ? qsTr("Привязать аккаунт")
                         : (root.inviteMode ? qsTr("Создать аккаунт") : qsTr("Войти")))
                visible: !root.inviteController.hasSession || root.canBindCredentials
                onClicked: root.submit()
            }

            ButtonType {
                id: retryButton
                objectName: "mayak-auth-retry"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: root.inviteController.hasSession
                enabled: visible && !root.inviteController.busy
                variant: ButtonType.Secondary
                text: {
                    if (root.inviteController.busy) return qsTr("Подождите…")
                    if (!root.inviteController.accountMetadataKnown) return qsTr("Проверить аккаунт")
                    return qsTr("Повторить настройку")
                }
                onClicked: root.inviteController.accountMetadataKnown
                           ? root.inviteController.retrySetup()
                           : root.inviteController.refreshAccount()
            }

            // Telegram по желанию: уведомления о новых устройствах и вход через Telegram.
            BodyTextType {
                objectName: "mayak-auth-telegram-state"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                wrapMode: Text.WordWrap
                // Имя из Telegram задаёт сам пользователь Telegram: только простой текст, без разметки.
                textFormat: Text.PlainText
                visible: root.inviteController.hasSession && root.inviteController.accountMetadataKnown
                text: {
                    if (root.inviteController.telegramLinked) {
                        return root.inviteController.telegramName.length > 0
                                ? qsTr("Telegram привязан: @%1").arg(root.inviteController.telegramName)
                                : qsTr("Telegram привязан.")
                    }
                    if (root.inviteController.telegramConfirmName.length > 0) {
                        return qsTr("Привязать Telegram %1 к этому аккаунту? Подтверждайте, только если это ваш Telegram.")
                                .arg(root.inviteController.telegramConfirmName)
                    }
                    return root.inviteController.telegramLinkPending
                            ? qsTr("Ждём нажатия «Запустить» в Telegram…")
                            : qsTr("Привяжите Telegram, чтобы получать уведомления о новых устройствах.")
                }
                color: AmneziaStyle.color.textSecondary
            }

            ButtonType {
                objectName: "mayak-auth-telegram-link"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: root.inviteController.hasSession && root.inviteController.accountMetadataKnown
                         && !root.inviteController.telegramLinked && root.inviteController.telegramConfirmName.length === 0
                enabled: visible && !root.inviteController.busy
                variant: ButtonType.Secondary
                text: root.inviteController.telegramLinkPending ? qsTr("Отменить привязку") : qsTr("Привязать Telegram")
                onClicked: root.inviteController.telegramLinkPending
                           ? root.inviteController.cancelTelegramLink()
                           : root.inviteController.linkTelegram()
            }

            RowLayout {
                objectName: "mayak-auth-telegram-confirm"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                spacing: 8
                visible: root.inviteController.hasSession && root.inviteController.telegramConfirmName.length > 0

                ButtonType {
                    Layout.fillWidth: true
                    text: qsTr("Да, это мой Telegram")
                    enabled: !root.inviteController.busy
                    onClicked: root.inviteController.confirmTelegramLink()
                }
                ButtonType {
                    Layout.fillWidth: true
                    text: qsTr("Нет")
                    variant: ButtonType.Secondary
                    enabled: !root.inviteController.busy
                    onClicked: root.inviteController.cancelTelegramLink()
                }
            }

            ButtonType {
                objectName: "mayak-auth-logout"
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                visible: root.inviteController.hasSession
                enabled: visible && !root.inviteController.busy
                variant: ButtonType.Text
                text: qsTr("Выйти из аккаунта")
                onClicked: {
                    root.inviteController.logout()
                    root.clearFields()
                }
            }

            Item { Layout.preferredHeight: 24 + PageController.safeAreaBottomMargin }
        }
    }

    function submit() {
        if (inviteController.busy) return
        suppressMessage = false
        if (inviteController.hasSession && canBindCredentials) {
            inviteController.bindCredentials(emailValue, passwordValue)
        } else if (inviteMode) {
            inviteController.registerAccount(inviteValue, emailValue, passwordValue)
        } else {
            inviteController.login(emailValue, passwordValue)
        }
    }

    Connections {
        target: root.inviteController
        function onStateChanged() {
            if (root.inviteController.busy) {
                root.sawBusy = true
            } else if (root.sawBusy) {
                root.clearPassword()
                root.sawBusy = false
            }
        }
        function onSetupFinished() {
            root.clearFields()
            root.pageController.goToPageHome()
        }
        function onOpenExternalUrl(url) {
            Qt.openUrlExternally(url)
        }
    }

    function formatSeen(value) {
        const date = new Date(value)
        return isNaN(date.getTime()) ? qsTr("неизвестно") : date.toLocaleDateString(Qt.locale(), Locale.ShortFormat)
    }

    Component.onCompleted: root.inviteController.refreshAccount()
}
