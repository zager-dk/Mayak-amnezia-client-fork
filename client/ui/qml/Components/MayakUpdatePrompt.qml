import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "../Controls2"
import "../Controls2/TextTypes"

SheetType {
    id: root
    objectName: "mayak-update-prompt"

    property Item focusTarget: null
    property Item previousFocusTarget: null
    property string versionText: ""
    property string offeredVersion: ""
    property string pendingVersion: ""
    property bool pendingManual: false
    property bool manualCheckPending: false
    property bool actionHandled: false
    property bool acceptingUpdate: false
    property var suppressedVersions: []

    readonly property bool authenticationBusy: typeof MayakInviteController !== "undefined"
                                               && MayakInviteController.busy
    readonly property int suppressedVersionCount: suppressedVersions.length

    showGrabber: true
    expandedHeight: content.implicitHeight + PageController.safeAreaBottomMargin + 80

    function wasSuppressed(version) {
        return suppressedVersions.indexOf(version) >= 0
    }

    function suppress(version) {
        if (version.length > 0 && !wasSuppressed(version))
            suppressedVersions = suppressedVersions.concat([version])
    }

    function offerUpdate(version, manual) {
        if (!version || (!manual && wasSuppressed(version))) return
        if (authenticationBusy) {
            pendingVersion = version
            pendingManual = manual
            return
        }
        if (opened) {
            if (version === offeredVersion) return
            pendingVersion = version
            pendingManual = manual
            return
        }
        offeredVersion = version
        versionText = version
        previousFocusTarget = focusTarget
        open()
    }

    function showPendingUpdate() {
        if (pendingVersion.length === 0 || authenticationBusy || opened) return
        const version = pendingVersion
        const manual = pendingManual
        pendingVersion = ""
        pendingManual = false
        offerUpdate(version, manual)
    }

    function acceptUpdate() {
        actionHandled = true
        acceptingUpdate = true
        suppress(offeredVersion)
        pendingVersion = ""
        close()
        Qt.callLater(function() {
            PageController.goToPage(PageEnum.PageUpdate)
        })
    }

    onOpened: updateButton.forceActiveFocus()
    onClosed: {
        if (!actionHandled) suppress(offeredVersion)
        actionHandled = false
        if (acceptingUpdate) {
            acceptingUpdate = false
            return
        }
        if (previousFocusTarget && previousFocusTarget.visible)
            previousFocusTarget.forceActiveFocus()
        Qt.callLater(showPendingUpdate)
    }

    ColumnLayout {
        id: content
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 14
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        spacing: 12

        H2TextType {
            objectName: "mayak-update-prompt-title"
            Layout.fillWidth: true
            text: qsTr("Доступно обновление Маяка")
            color: AmneziaStyle.color.textPrimary
            wrapMode: Text.WordWrap
        }

        BodyTextType {
            objectName: "mayak-update-prompt-version"
            Layout.fillWidth: true
            text: qsTr("Версия %1 уже доступна. Обновить сейчас или продолжить работу?").arg(root.versionText)
            color: AmneziaStyle.color.textSecondary
            wrapMode: Text.WordWrap
        }

        ButtonType {
            id: updateButton
            objectName: "mayak-update-prompt-update"
            Layout.fillWidth: true
            text: qsTr("Обновить")
            Keys.onPressed: function(event) {
                if (event.key === Qt.Key_Back) {
                    root.close()
                    event.accepted = true
                }
            }
            onClicked: root.acceptUpdate()
        }

        ButtonType {
            objectName: "mayak-update-prompt-later"
            Layout.fillWidth: true
            variant: ButtonType.Secondary
            text: qsTr("Позже")
            onClicked: {
                root.actionHandled = true
                root.suppress(root.offeredVersion)
                root.close()
            }
        }

        Item { Layout.preferredHeight: PageController.safeAreaBottomMargin + 12 }
    }

    Connections {
        target: UpdateController

        function onManualCheckStarted() { root.manualCheckPending = true }
        function onUpdateFound() {
            const manual = root.manualCheckPending
            root.manualCheckPending = false
            root.offerUpdate(UpdateController.version, manual)
        }
        function onUpdateNotFound() { root.manualCheckPending = false }
        function onUpdateCheckFailed() { root.manualCheckPending = false }
    }

    Connections {
        target: typeof MayakInviteController !== "undefined" ? MayakInviteController : null
        function onStateChanged() {
            if (!root.authenticationBusy) Qt.callLater(root.showPendingUpdate)
        }
    }
}
