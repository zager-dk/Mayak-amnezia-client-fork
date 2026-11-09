import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Style 1.0
import "../Controls2"
import "../Controls2/TextTypes"
import "../Components"
import "../MayakCity"
import "../MayakCity/MayakCity.js" as CityData

PageType {
    id: root
    isTabBarHidden: true
    // Read-only selected-exit contract; empty or unmatched metadata is unknown.
    readonly property var exitLocation: typeof ConnectionController.exitLocation !== "undefined"
                                        ? ConnectionController.exitLocation : ({ candidateId: "", cityId: "" })
    property bool cityDetailsOpen: false
    readonly property bool knownCitySelected: !!exitLocation
                                              && typeof exitLocation.candidateId === "string"
                                              && exitLocation.candidateId.length > 0
                                              && CityData.cityForId(exitLocation.cityId) !== null
    readonly property var resolvedCity: knownCitySelected ? CityData.cityForId(exitLocation.cityId) : null
    readonly property bool cityVisible: connectButton.archivePhase === "Connected" && connectButton.beamSettled && knownCitySelected
    property real beaconDiameter: Math.min(470, width * 0.63, height * 0.42)
    readonly property string waitingPhase: ["Fetching", "Admitting", "Starting", "Verifying"].indexOf(connectButton.archivePhase) >= 0 ? connectButton.archivePhase : ""
    property bool longWait: false
    property bool cancelRequested: false
    readonly property real heroTopGap: root.cityDetailsOpen
                                       ? Math.max(0, root.height * 0.735 - (18 + PageController.safeAreaTopMargin + 48 + 16))
                                       : Math.max(0, root.height * 0.38 - (18 + PageController.safeAreaTopMargin + 48 + 16) - beaconDiameter / 2)
    function resetWaitFeedback() { longWait = false; cancelRequested = false; phaseWaitTimer.stop(); if (waitingPhase !== "") phaseWaitTimer.start() }
    function collapseDetails() { cityDetailsOpen = false }
    Component.onCompleted: resetWaitFeedback()
    onWaitingPhaseChanged: resetWaitFeedback()
    onCityVisibleChanged: if (!cityVisible) collapseDetails()
    Timer { id: phaseWaitTimer; interval: 10001; repeat: false; onTriggered: root.longWait = root.waitingPhase !== "" && !root.cancelRequested }
    Connections { target: connectButton; function onClicked() { root.longWait = false; phaseWaitTimer.stop(); if (root.waitingPhase !== "") root.cancelRequested = true } }

    Rectangle { anchors.fill: parent; color: AmneziaStyle.color.mayakSurface0; z: -3 }
    MayakCityScene {
        id: cityScene
        anchors.fill: parent
        z: -0.5
        photoSource: root.resolvedCity ? root.resolvedCity.photo : ""
        sceneActive: root.cityVisible
        reduceMotion: AmneziaStyle.mayakReduceMotion
        detailsScrollOffset: root.cityDetailsOpen ? detailsScroll.contentY * 0.35 : 0
    }

    ColumnLayout {
        anchors.fill: parent; anchors.leftMargin: 18; anchors.rightMargin: 18
        anchors.topMargin: 18 + PageController.safeAreaTopMargin; anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
        spacing: 8
        RowLayout {
            Layout.fillWidth: true; Layout.minimumHeight: 48; spacing: 10
            ToolButton {
                objectName: "mayak-brand-settings"; Layout.preferredWidth: 116; Layout.preferredHeight: 48
                Accessible.name: qsTr("Маяк — настройки, обновления и аккаунт"); ToolTip.text: Accessible.name; ToolTip.visible: hovered
                onClicked: PageController.goToPage(PageEnum.PageSettings)
                contentItem: RowLayout { spacing: 7
                    Image { Layout.preferredWidth: 32; Layout.preferredHeight: 32; source: "qrc:/images/mayak-mark-round-128.png"; fillMode: Image.PreserveAspectFit; Accessible.ignored: true }
                    Text { objectName: "mayak-wordmark"; text: "маяк"; color: root.cityVisible ? "#ECEFF6" : AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 21; font.weight: Font.DemiBold }
                }
                background: Item {}
            }
            Item { Layout.fillWidth: true }
            ToolButton {
                objectName: "mayak-theme-toggle"; Layout.preferredWidth: 48; Layout.preferredHeight: 48
                text: AmneziaStyle.mayakDay ? "☾" : "☼"; font.pixelSize: 22; Accessible.name: AmneziaStyle.mayakDay ? qsTr("Включить ночную тему") : qsTr("Включить дневную тему")
                onClicked: AmneziaStyle.mayakDay = !AmneziaStyle.mayakDay
                background: Rectangle { radius: 14; color: parent.visualFocus ? (root.cityVisible ? "#66111827" : AmneziaStyle.color.mayakSurface1) : "transparent"; border.width: parent.visualFocus ? 2 : 0; border.color: AmneziaStyle.color.mayakFocus }
                contentItem: Text { text: parent.text; color: root.cityVisible ? "#ECEFF6" : AmneziaStyle.color.mayakInk; font: parent.font; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
            }
        }
        Item { Layout.preferredHeight: root.heroTopGap; Layout.minimumHeight: 0; Layout.maximumHeight: root.heroTopGap }
        ConnectButton {
            id: connectButton; objectName: "mayak-main-connect"; Layout.alignment: Qt.AlignHCenter
            exitLocation: root.exitLocation
            citySceneActive: root.cityVisible
            beaconDiameter: root.beaconDiameter; Layout.preferredWidth: Math.min(Math.max(204, beaconDiameter), root.width - 36); Layout.preferredHeight: implicitHeight
            opacity: root.cityDetailsOpen ? 0 : 1; visible: opacity > 0
            Behavior on opacity { NumberAnimation { duration: AmneziaStyle.mayakReduceMotion ? 0 : 240 } }
            text: archivePhase === "CleanupPending" ? qsTr("Повторить отключение") : archivePhase === "Stopping" ? qsTr("Отключаем…") : ["Fetching", "Admitting", "Starting", "Verifying"].indexOf(archivePhase) >= 0 || (archivePhase === "Idle" && inProgress) ? qsTr("Подключаем…") : archivePhase === "Preparing" ? ConnectionController.connectionStateText : connected ? qsTr("Выключить Маяк") : qsTr("Включить Маяк")
            Accessible.name: text; Accessible.description: ConnectionController.connectionStateText
        }
        BodyTextType {
            objectName: "mayak-home-helper"; Layout.fillWidth: true; Layout.minimumHeight: 40
            visible: !root.cityVisible && !root.cityDetailsOpen && !connectButton.showUnknownCityCard; text: qsTr("Выход выбирается автоматически")
            horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap; color: AmneziaStyle.color.mayakInkMuted
        }
        BodyTextType {
            objectName: "mayak-connection-phase-status"; Layout.fillWidth: true; Layout.minimumHeight: 36
            visible: !root.cityVisible && !connectButton.showUnknownCityCard && !root.cityDetailsOpen && !["Idle", "Connected"].includes(connectButton.archivePhase)
            text: { switch (connectButton.archivePhase) { case "Fetching": return qsTr("Этап 1 из 4 · Получаем настройки"); case "Admitting": return qsTr("Этап 2 из 4 · Выбираем выход"); case "Starting": return qsTr("Этап 3 из 4 · Запускаем туннель"); case "Verifying": return qsTr("Этап 4 из 4 · Проверяем соединение"); case "Stopping": return qsTr("Отключаем…"); case "Cancelled": return qsTr("Подключение отменено"); case "Failed": return ConnectionController.connectionStateText; default: return ConnectionController.connectionStateText } }
            horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; wrapMode: Text.WordWrap; color: AmneziaStyle.color.mayakInkMuted
        }
        BodyTextType { objectName: "mayak-long-wait-hint"; Layout.fillWidth: true; visible: root.waitingPhase !== "" && root.longWait && !root.cancelRequested; text: qsTr("Это занимает дольше обычного"); horizontalAlignment: Text.AlignHCenter; color: AmneziaStyle.color.mayakInkMuted }
        Button {
            id: cancelButton; objectName: "mayak-cancel-connect"
            Layout.alignment: Qt.AlignHCenter; Layout.preferredWidth: Math.min(180, root.width - 36); Layout.preferredHeight: 48
            visible: root.waitingPhase !== "" && !root.cancelRequested
            text: qsTr("Отменить"); Accessible.name: text
            font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 16
            onClicked: {
                if (activeFocus) connectButton.forceActiveFocus()
                connectButton.clicked()
            }
            Keys.onReturnPressed: cancelButton.clicked()
            Keys.onEnterPressed: cancelButton.clicked()
            background: Rectangle {
                radius: 14
                color: cancelButton.down ? AmneziaStyle.color.mayakSurface2 : AmneziaStyle.color.mayakSurface1
                border.width: cancelButton.visualFocus ? 2 : 1
                border.color: cancelButton.visualFocus ? AmneziaStyle.color.mayakFocus : AmneziaStyle.color.mayakLine
            }
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 0; visible: root.cityVisible && !root.cityDetailsOpen }
        Rectangle {
            id: cityCard; objectName: "mayak-city-card"; Layout.fillWidth: true; Layout.maximumWidth: 520; Layout.alignment: Qt.AlignHCenter
            Layout.preferredHeight: implicitHeight; implicitHeight: cardColumn.implicitHeight + 38
            opacity: root.cityVisible && !root.cityDetailsOpen ? 1 : 0; visible: opacity > 0.001
            transform: Translate { y: 24 * (1 - cityCard.opacity) }
            Behavior on opacity { NumberAnimation { duration: AmneziaStyle.mayakReduceMotion ? 0 : 300; easing.type: Easing.OutCubic } }
            activeFocusOnTab: true; Accessible.role: Accessible.Button; Accessible.name: root.resolvedCity ? root.resolvedCity.title : ""
            Accessible.description: qsTr("Потяните вверх или нажмите, чтобы открыть фото и подробности")
            Keys.onReturnPressed: root.cityDetailsOpen = true; Keys.onEnterPressed: root.cityDetailsOpen = true
            radius: 24; color: AmneziaStyle.mayakDay ? "#f7f8fb" : "#ed0b1120"; border.width: 1; border.color: AmneziaStyle.mayakDay ? "#dcd7cc" : "#343b50"
            ColumnLayout { id: cardColumn; anchors.fill: parent; anchors.margins: 18; spacing: 9
                Item { Layout.fillWidth: true; Layout.preferredHeight: 4
                    Rectangle { anchors.centerIn: parent; width: 36; height: 4; radius: 2; color: AmneziaStyle.mayakDay ? "#9A9FAB" : "#5E6880" }
                }
                Text { text: "●  СОЕДИНЕНИЕ ПРОВЕРЕНО"; color: AmneziaStyle.semanticPalette.ok; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 14; font.weight: Font.DemiBold }
                Text { objectName: "mayak-city-title"; Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.title : ""; color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 25; font.weight: Font.DemiBold; wrapMode: Text.WordWrap }
                Text { Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.shortText : ""; color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 17; wrapMode: Text.WordWrap }
                Text { Layout.fillWidth: true; text: "⌃  Потяните вверх: фото и подробности"; color: AmneziaStyle.color.mayakBeam; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 15; font.weight: Font.DemiBold }
            }
            MouseArea {
                anchors.fill: parent
                onClicked: root.cityDetailsOpen = true
                onPressed: function(mouse) { cityCard.yStart = mouse.y }
                onReleased: function(mouse) { if (cityCard.yStart - mouse.y > 36) root.cityDetailsOpen = true }
            }
            property real yStart: 0
        }
        Rectangle {
            objectName: "mayak-unknown-city-card"; visible: connectButton.showUnknownCityCard && !root.knownCitySelected
            Layout.fillWidth: true; Layout.preferredHeight: 56; radius: 18; color: AmneziaStyle.color.mayakSurface1; border.width: 1; border.color: AmneziaStyle.color.mayakLine
            Accessible.role: Accessible.StaticText; Accessible.name: qsTr("Вы за рубежом")
            Text { anchors.centerIn: parent; text: qsTr("Вы за рубежом"); color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 16; font.weight: Font.DemiBold }
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 0; visible: !root.cityVisible }
    }
    Rectangle {
        id: cityDetails; objectName: "mayak-city-details"
        width: Math.min(620, root.width - 36)
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top; anchors.bottom: parent.bottom
        anchors.topMargin: root.height * 0.735 - Math.max(0, (720 - root.height) * 0.65)
        anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
        z: 2; color: "transparent"
        visible: root.cityVisible && root.cityDetailsOpen
        ColumnLayout { anchors.fill: parent; anchors.leftMargin: 18; anchors.rightMargin: 18; spacing: 8
            ToolButton { text: "‹  Назад"; Accessible.name: qsTr("Свернуть подробности города"); onClicked: root.collapseDetails() }
            Item {
                objectName: "mayak-details-swipe-handle"
                Layout.fillWidth: true; Layout.preferredHeight: 18
                Rectangle { anchors.centerIn: parent; width: 36; height: 4; radius: 2; color: "#8a9ab7" }
                MouseArea {
                    anchors.fill: parent; property real dragStartY: 0
                    onPressed: function(mouse) { dragStartY = mouse.y }
                    onReleased: function(mouse) {
                        if (detailsScroll.contentY <= 0 && mouse.y - dragStartY > 36) root.collapseDetails()
                    }
                }
            }
            Text { Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.title : ""; color: "#ECEFF6"; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 26; font.weight: Font.DemiBold; wrapMode: Text.WordWrap }
            Flickable { id: detailsScroll; objectName: "mayak-details-scroll"; Layout.fillWidth: true; Layout.fillHeight: true; Layout.minimumHeight: 60; contentHeight: detailsContent.implicitHeight; clip: true; boundsBehavior: Flickable.StopAtBounds
                ColumnLayout { id: detailsContent; width: detailsScroll.width; spacing: 14
                    Repeater { objectName: "mayak-city-paragraphs"; model: root.resolvedCity ? root.resolvedCity.paragraphs : []; delegate: Text { Layout.fillWidth: true; text: modelData; wrapMode: Text.WordWrap; color: "#ECEFF6"; font.pixelSize: 16 } }
                    Text { text: qsTr("Что посмотреть"); color: "#ECEFF6"; font.pixelSize: 20; font.weight: Font.DemiBold }
                    Repeater { objectName: "mayak-city-sights"; model: root.resolvedCity ? root.resolvedCity.sights : []; delegate: ColumnLayout { Layout.fillWidth: true; spacing: 2; Text { text: modelData[0]; color: AmneziaStyle.color.mayakBeam; font.pixelSize: 16; font.weight: Font.DemiBold } Text { Layout.fillWidth: true; text: modelData[1]; color: "#CFD5E1"; font.pixelSize: 15; wrapMode: Text.WordWrap } } }
                    Text { objectName: "mayak-city-photo-credit"; Layout.fillWidth: true; text: root.resolvedCity ? qsTr("Фото: %1, «%2», %3 · %4 (%5). Source: %6.").arg(root.resolvedCity.author).arg(root.resolvedCity.photoTitle).arg(root.resolvedCity.license).arg(root.resolvedCity.licenseUrl).arg(root.resolvedCity.source).arg(root.resolvedCity.sourceUrl) : ""; color: "#CFD5E1"; font.pixelSize: 13; wrapMode: Text.WordWrap }
                    Text { Layout.fillWidth: true; text: qsTr("Город выхода показан по данным сервера."); color: "#CFD5E1"; font.pixelSize: 13; wrapMode: Text.WordWrap }
                }
            }
        }
    }
    Keys.onEscapePressed: if (cityDetailsOpen) collapseDetails()
    Keys.onBackPressed: if (cityDetailsOpen) collapseDetails()
}
