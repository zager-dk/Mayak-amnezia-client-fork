import QtQuick
import QtQuick.Controls
import QtQuick.Window
import Style 1.0
import "../Controls2/TextTypes"
import "../newComponents/Mayak"

Button {
    id: root

    property bool connected: ConnectionController.isConnected
    property bool inProgress: ConnectionController.isConnectionInProgress
    readonly property string archivePhase: {
        if (ConnectionController.cleanupPending) return "CleanupPending"
        switch (ConnectionController.connectionPhase) {
        case "preparing": return "Preparing"
        case "fetching": return "Fetching"
        case "admitting": return "Admitting"
        case "starting": return "Starting"
        case "verifying": return "Verifying"
        case "connected": return "Connected"
        case "stopping": return "Stopping"
        case "failed": return "Failed"
        case "cancelled": return "Cancelled"
        default: return "Idle"
        }
    }
    property bool beamSettled: false
    // V3A intentionally exposes no location DTO; never infer a city from connection/IP.
    readonly property bool showUnknownCityCard: connected && archivePhase === "Connected" && beamSettled
    onArchivePhaseChanged: if (archivePhase !== "Connected") beamSettled = false
    // Scene size is independent of the action label and adapts to the home viewport.
    property real beaconDiameter: 204
    readonly property bool motionActive: Qt.application.state === Qt.ApplicationActive
                                        && root.Window.window !== null
                                        && root.Window.window.visibility !== Window.Minimized

    implicitWidth: Math.max(204, beaconDiameter)
    implicitHeight: beaconDiameter + 16 + label.implicitHeight
    padding: 0
    hoverEnabled: true
    text: ConnectionController.connectionStateText

    Connections {
        target: ConnectionController
        function onPreparingConfig() {
            PageController.showNotificationMessage(qsTr("Unable to disconnect during configuration preparation"))
        }
    }

    background: Item {}
    contentItem: Item {
        MayakBeacon {
            id: beacon
            objectName: "mayak-beacon-decoration"
            anchors.horizontalCenter: parent.horizontalCenter
            width: root.beaconDiameter
            height: width
            phase: root.archivePhase
            active: root.motionActive
            reduceMotion: AmneziaStyle.mayakReduceMotion
            ringOffColor: AmneziaStyle.color.mayakLineStrong
            scale: root.down ? 0.97 : 1
            opacity: root.down ? 0.90 : 1
            Behavior on scale { NumberAnimation { duration: AmneziaStyle.mayakReduceMotion ? 0 : (root.down ? 90 : 120); easing.type: Easing.OutQuad } }
            Behavior on opacity { NumberAnimation { duration: AmneziaStyle.mayakReduceMotion ? 0 : (root.down ? 90 : 120) } }
        }
        Rectangle {
            anchors.centerIn: beacon
            width: beacon.width + 8
            height: width
            radius: width / 2
            color: "transparent"
            border.width: 2
            border.color: AmneziaStyle.color.mayakFocus
            visible: root.visualFocus
        }
        ButtonTextType {
            id: label
            objectName: "mayak-main-connect-label"
            y: root.beaconDiameter + 16
            width: parent.width
            height: implicitHeight
            text: root.text
            color: AmneziaStyle.color.mayakInk
            lineHeight: 30 + LanguageUiController.getLineHeightAppend()
            font.pixelSize: 20
            font.weight: 700
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            wrapMode: Text.WordWrap
        }
    }

    Connections {
        target: beacon
        function onBeamSettled() { root.beamSettled = true }
    }

    HoverHandler { cursorShape: Qt.PointingHandCursor }
    onClicked: ConnectionController.connectButtonClicked()
    Keys.onEnterPressed: root.clicked()
    Keys.onReturnPressed: root.clicked()
}
