import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Style 1.0
import "../Controls2"
import "../Controls2/TextTypes"
import "../Components"

PageType {
    id: root
    // The animated scene is large like the user's home reference; standalone icons are separate.
    property real beaconDiameter: Math.min(360, root.width * 0.63, root.height * 0.42)
    // Elapsed time affects guidance only. The controller remains the phase authority.
    readonly property string waitingPhase: ["Fetching", "Admitting", "Starting", "Verifying"]
        .indexOf(connectButton.archivePhase) >= 0 ? connectButton.archivePhase : ""
    property bool longWait: false
    property bool cancelRequested: false

    function resetWaitFeedback() {
        longWait = false
        cancelRequested = false
        phaseWaitTimer.stop()
        if (waitingPhase !== "") phaseWaitTimer.start()
    }

    Component.onCompleted: resetWaitFeedback()
    onWaitingPhaseChanged: resetWaitFeedback()

    Timer {
        id: phaseWaitTimer
        interval: 10001
        repeat: false
        onTriggered: root.longWait = root.waitingPhase !== "" && !root.cancelRequested
    }

    Connections {
        target: connectButton
        function onClicked() {
            root.longWait = false
            phaseWaitTimer.stop()
            // Suppress a second local cancellation while the real controller handles it.
            if (root.waitingPhase !== "") root.cancelRequested = true
        }
    }

    Rectangle {
        anchors.fill: parent
        color: AmneziaStyle.color.mayakSurface0
        z: -1
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        anchors.topMargin: 18 + PageController.safeAreaTopMargin
        anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
        spacing: 8

        RowLayout {
            Layout.fillWidth: true
            Layout.minimumHeight: 48
            spacing: 10
            Image {
                Layout.preferredWidth: 32
                Layout.preferredHeight: 32
                // Use the archive's antialiased transparent circular raster: Qt's SVG
                // backend in this build does not honor the source circle clipPath.
                source: "qrc:/images/mayak-mark-round-128.png"
                fillMode: Image.PreserveAspectFit
                Accessible.ignored: true
            }
            Text {
                Layout.fillWidth: true
                objectName: "mayak-wordmark"
                text: "маяк"
                color: AmneziaStyle.color.mayakInk
                font.family: AmneziaStyle.uiFontFamily
                font.pixelSize: 22
                font.weight: Font.DemiBold
                Accessible.name: qsTr("Маяк")
            }
            ToolButton {
                objectName: "mayak-theme-toggle"
                Layout.preferredWidth: 48
                Layout.preferredHeight: 48
                text: AmneziaStyle.mayakDay ? "☾" : "☼"
                font.pixelSize: 22
                hoverEnabled: true
                Accessible.name: AmneziaStyle.mayakDay ? qsTr("Включить ночную тему") : qsTr("Включить дневную тему")
                onClicked: AmneziaStyle.mayakDay = !AmneziaStyle.mayakDay
                background: Rectangle {
                    radius: 14
                    color: parent.down ? AmneziaStyle.color.mayakSurface2 : AmneziaStyle.color.mayakSurface1
                    border.width: parent.visualFocus ? 2 : 1
                    border.color: parent.visualFocus ? AmneziaStyle.color.mayakFocus : AmneziaStyle.color.mayakLine
                }
                contentItem: Text {
                    text: parent.text
                    color: AmneziaStyle.color.mayakBeam
                    font: parent.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
        BodyTextType {
            Layout.fillWidth: true
            text: qsTr("Свободный сервер выбирается автоматически")
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.mayakInkMuted
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 4 }

        ConnectButton {
            id: connectButton
            objectName: "mayak-main-connect"
            Layout.alignment: Qt.AlignHCenter
            beaconDiameter: root.beaconDiameter
            Layout.preferredWidth: Math.min(Math.max(204, beaconDiameter), root.width - 36)
            Layout.preferredHeight: implicitHeight
            text: archivePhase === "CleanupPending" ? qsTr("Повторить отключение")
                  : archivePhase === "Stopping" ? qsTr("Отключаем…")
                  : ["Fetching", "Admitting", "Starting", "Verifying"].indexOf(archivePhase) >= 0
                    || (archivePhase === "Idle" && inProgress) ? qsTr("Подключаем…")
                  : archivePhase === "Preparing" ? ConnectionController.connectionStateText
                  : connected ? qsTr("Выключить Маяк") : qsTr("Включить Маяк")
            Accessible.name: text
            Accessible.description: ConnectionController.connectionStateText
        }

        Rectangle {
            objectName: "mayak-unknown-city-card"
            visible: connectButton.showUnknownCityCard
            Layout.fillWidth: true
            Layout.preferredHeight: 56
            radius: 18
            color: AmneziaStyle.color.mayakSurface1
            border.width: 1
            border.color: AmneziaStyle.color.mayakLine
            Accessible.role: Accessible.StaticText
            Accessible.name: qsTr("Вы за рубежом")
            Text {
                anchors.centerIn: parent
                text: qsTr("Вы за рубежом")
                color: AmneziaStyle.color.mayakInk
                font.family: AmneziaStyle.uiFontFamily
                font.pixelSize: 16
                font.weight: Font.DemiBold
            }
        }
        BodyTextType {
            objectName: "mayak-connection-phase-status"
            Layout.fillWidth: true
            Layout.minimumHeight: 36
            visible: !connectButton.showUnknownCityCard
            text: {
                switch (connectButton.archivePhase) {
                case "Fetching": return qsTr("Этап 1 из 4 · Получаем настройки")
                case "Admitting": return qsTr("Этап 2 из 4 · Выбираем выход")
                case "Starting": return qsTr("Этап 3 из 4 · Запускаем туннель")
                case "Verifying": return qsTr("Этап 4 из 4 · Проверяем соединение")
                case "Stopping": return qsTr("Отключаем…")
                case "Cancelled": return qsTr("Подключение отменено")
                case "Failed": return ConnectionController.connectionStateText
                default: return ConnectionController.connectionStateText
                }
            }
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.mayakInkMuted
        }
        BodyTextType {
            objectName: "mayak-long-wait-hint"
            Layout.fillWidth: true
            visible: root.waitingPhase !== "" && root.longWait && !root.cancelRequested
            text: qsTr("Это занимает дольше обычного")
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.mayakInkMuted
        }
        Button {
            id: cancelButton
            objectName: "mayak-cancel-connect"
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: Math.min(180, root.width - 36)
            Layout.preferredHeight: 48
            visible: root.waitingPhase !== "" && !root.cancelRequested
            enabled: visible
            text: qsTr("Отменить")
            Accessible.name: text
            font.family: AmneziaStyle.uiFontFamily
            font.pixelSize: 16
            focusPolicy: Qt.StrongFocus
            onClicked: {
                if (activeFocus) connectButton.forceActiveFocus()
                connectButton.clicked()
            }
            Keys.onReturnPressed: clicked()
            Keys.onEnterPressed: clicked()
            background: Rectangle {
                radius: 14
                color: cancelButton.down ? AmneziaStyle.color.mayakSurface2 : AmneziaStyle.color.mayakSurface1
                border.width: cancelButton.visualFocus ? 2 : 1
                border.color: cancelButton.visualFocus ? AmneziaStyle.color.mayakFocus : AmneziaStyle.color.mayakLine
            }
            contentItem: Text {
                text: cancelButton.text
                color: AmneziaStyle.color.mayakInk
                font: cancelButton.font
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
            }
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 4 }

    }
}
