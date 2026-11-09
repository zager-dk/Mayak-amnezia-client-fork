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
    property real detailsProgress: 0
    readonly property real detailsBodyOpacity: Math.max(0, 2 * detailsProgress - 1)
    property bool detailDragActive: false
    property real collapsedTitleY: 0
    property real collapsedTitleX: 0
    property real collapsedTitleWidth: 0
    readonly property bool knownCitySelected: !!exitLocation
                                              && typeof exitLocation.candidateId === "string"
                                              && exitLocation.candidateId.length > 0
                                              && CityData.cityForId(exitLocation.cityId) !== null
    readonly property var resolvedCity: knownCitySelected ? CityData.cityForId(exitLocation.cityId) : null
    readonly property bool cityVisible: connectButton.archivePhase === "Connected" && connectButton.beamSettled && knownCitySelected
    property real cityCardReveal: cityVisible ? 1 : 0
    Behavior on cityCardReveal { NumberAnimation { duration: AmneziaStyle.mayakReduceMotion ? 0 : 300; easing.type: Easing.OutCubic } }
    readonly property real desiredBeaconDiameter: Math.min(470, width * 0.63, height * 0.42)
    readonly property real connectedActionTop: detailsTopY + 12
    readonly property real connectedActionBottom: cityCard.y - 12
    readonly property real connectedActionHeight: Math.max(0, connectedActionBottom - connectedActionTop)
    property real beaconDiameter: cityVisible
                                  ? Math.min(desiredBeaconDiameter, Math.max(0, connectedActionHeight
                                      - connectButton.actionLabelSpacing - connectButton.actionLabelHeight))
                                  : desiredBeaconDiameter
    readonly property string waitingPhase: ["Fetching", "Admitting", "Starting", "Verifying"].indexOf(connectButton.archivePhase) >= 0 ? connectButton.archivePhase : ""
    property bool longWait: false
    property bool cancelRequested: false
    // Keep the home composition fixed while the city layer fades over it.
    // The collapsed title position is measured from the live card below.
    readonly property real heroTopGap: Math.max(0, root.height * 0.38 - (18 + PageController.safeAreaTopMargin + 48 + 16) - beaconDiameter / 2)
    readonly property real detailsTopY: 18 + PageController.safeAreaTopMargin + 48 + 8
    function resetWaitFeedback() { longWait = false; cancelRequested = false; phaseWaitTimer.stop(); if (waitingPhase !== "") phaseWaitTimer.start() }
    function collapseDetails() { cityDetailsOpen = false }
    function revealDetails() {
        if (!detailDragActive) {
            collapsedTitleY = cardTitle.mapToItem(root, 0, 0).y
            collapsedTitleX = cardTitle.mapToItem(root, 0, 0).x
            collapsedTitleWidth = cardTitle.width
        }
        cityDetailsOpen = true
    }
    onCityDetailsOpenChanged: {
        if (cityDetailsOpen && collapsedTitleY <= 0 && cardTitle) {
            collapsedTitleY = cardTitle.mapToItem(root, 0, 0).y
            collapsedTitleX = cardTitle.mapToItem(root, 0, 0).x
            collapsedTitleWidth = cardTitle.width
        }
        detailProgressAnimation.stop()
        if (detailsScroll) {
            detailsScroll.cancelFlick()
            detailsScroll.contentY = 0
        }
        detailProgressAnimation.from = detailsProgress
        detailProgressAnimation.to = cityDetailsOpen ? 1 : 0
        detailProgressAnimation.duration = AmneziaStyle.mayakReduceMotion ? 0 : (cityDetailsOpen ? 400 : 260)
        detailProgressAnimation.start()
    }
    Component.onCompleted: resetWaitFeedback()
    onWaitingPhaseChanged: resetWaitFeedback()
    onCityVisibleChanged: if (!cityVisible) collapseDetails()
    Timer { id: phaseWaitTimer; interval: 10001; repeat: false; onTriggered: root.longWait = root.waitingPhase !== "" && !root.cancelRequested }
    NumberAnimation { id: detailProgressAnimation; target: root; property: "detailsProgress"; easing.type: Easing.OutCubic }
    Connections { target: connectButton; function onClicked() { root.longWait = false; phaseWaitTimer.stop(); if (root.waitingPhase !== "") root.cancelRequested = true } }

    Rectangle { anchors.fill: parent; color: AmneziaStyle.color.mayakSurface0; z: -3 }
    MayakCityScene {
        id: cityScene
        anchors.fill: parent
        z: -0.5
        photoSource: root.resolvedCity ? root.resolvedCity.photo : ""
        sceneActive: root.cityVisible
        detailsProgress: root.detailsProgress
        reduceMotion: AmneziaStyle.mayakReduceMotion
        detailsScrollOffset: root.cityDetailsOpen && !AmneziaStyle.mayakReduceMotion ? detailsScroll.contentY * 0.35 : 0
    }

    ColumnLayout {
        anchors.fill: parent; anchors.leftMargin: 18; anchors.rightMargin: 18
        anchors.topMargin: 18 + PageController.safeAreaTopMargin; anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
        spacing: 8
        RowLayout {
            id: homeHeader
            objectName: "mayak-home-header"
            z: 3
            Layout.fillWidth: true; Layout.minimumHeight: 48; spacing: 10
            ToolButton {
                objectName: "mayak-brand-settings"; Layout.preferredWidth: 116; Layout.preferredHeight: 48
                visible: !root.cityDetailsOpen
                Accessible.name: qsTr("Маяк — настройки, обновления и аккаунт"); ToolTip.text: Accessible.name; ToolTip.visible: hovered
                onClicked: PageController.goToPage(PageEnum.PageSettings)
                contentItem: RowLayout { spacing: 7
                    Image { Layout.preferredWidth: 32; Layout.preferredHeight: 32; source: "qrc:/images/mayak-mark-round-128.png"; fillMode: Image.PreserveAspectFit; Accessible.ignored: true }
                    Text { objectName: "mayak-wordmark"; text: "маяк"; color: root.cityVisible ? "#ECEFF6" : AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 21; font.weight: Font.DemiBold }
                }
                background: Item {}
            }
            ToolButton {
                objectName: "mayak-city-back"; Layout.preferredWidth: 48; Layout.preferredHeight: 48
                visible: root.cityDetailsOpen
                Accessible.name: qsTr("Свернуть подробности города")
                text: "‹"
                font.pixelSize: 34
                onClicked: root.collapseDetails()
                background: Item {}
                contentItem: Text { text: parent.text; color: root.cityVisible ? "#ECEFF6" : AmneziaStyle.color.mayakInk; font: parent.font; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
            }
            Item { Layout.fillWidth: true }
            ToolButton {
                objectName: "mayak-theme-toggle"; Layout.preferredWidth: 48; Layout.preferredHeight: 48
                Accessible.name: AmneziaStyle.mayakDay ? qsTr("Включить ночную тему") : qsTr("Включить дневную тему")
                onClicked: AmneziaStyle.mayakDay = !AmneziaStyle.mayakDay
                background: Rectangle { radius: 14; color: root.cityVisible ? "#A60A0F1C" : parent.visualFocus ? AmneziaStyle.color.mayakSurface1 : "transparent"; border.width: parent.visualFocus ? 2 : 0; border.color: AmneziaStyle.color.mayakFocus }
                contentItem: Image { objectName: "mayak-theme-svg-icon"; source: AmneziaStyle.mayakDay ? (root.cityVisible ? "qrc:/ui/qml/MayakCity/icons/moon.svg" : "qrc:/ui/qml/MayakCity/icons/moon-day.svg") : "qrc:/ui/qml/MayakCity/icons/sun.svg"; sourceSize: Qt.size(24, 24); fillMode: Image.PreserveAspectFit; Accessible.ignored: true }
            }
        }
        Item { objectName: "mayak-hero-spacer"; visible: !root.cityVisible; Layout.preferredHeight: root.heroTopGap; Layout.minimumHeight: 0; Layout.maximumHeight: root.heroTopGap }
        Item {
            id: connectSlot; objectName: "mayak-main-connect-slot"
            visible: !root.cityVisible
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: Math.min(Math.max(204, root.beaconDiameter), root.width - 36)
            Layout.preferredHeight: connectButton.implicitHeight
            opacity: 0
            enabled: false
            Accessible.ignored: true
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
            KeyNavigation.backtab: connectButton
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
        // Connected only needs the header in this layout. Its card and action
        // have one independent, stable geometry model below.
        Item { Layout.fillHeight: true; Layout.minimumHeight: 0; visible: root.cityVisible }
        Rectangle {
            objectName: "mayak-unknown-city-card"; visible: connectButton.showUnknownCityCard && !root.knownCitySelected
            Layout.fillWidth: true; Layout.preferredHeight: 56; radius: 18; color: AmneziaStyle.color.mayakSurface1; border.width: 1; border.color: AmneziaStyle.color.mayakLine
            Accessible.role: Accessible.StaticText; Accessible.name: qsTr("Вы за рубежом")
            Text { anchors.centerIn: parent; text: qsTr("Вы за рубежом"); color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 16; font.weight: Font.DemiBold }
        }
        Item { Layout.fillHeight: true; Layout.minimumHeight: 0; visible: !root.cityVisible }
    }
    Rectangle {
        id: cityCard; objectName: "mayak-city-card"
        width: Math.min(520, Math.max(0, root.width - 36))
        x: (root.width - width) / 2
        y: root.height - PageController.safeAreaBottomMargin - 14 - height
        height: implicitHeight; implicitHeight: cardColumn.implicitHeight + 38
        opacity: root.cityCardReveal * Math.max(0, 1 - 2 * root.detailsProgress)
        // Opacity is visual only: an in-flight card drag must retain its grab
        // even after the card has faded. The reader owns normal expanded input.
        visible: root.cityVisible
        activeFocusOnTab: root.detailsProgress < 0.5
        Accessible.ignored: root.detailsProgress >= 0.5
        Accessible.role: Accessible.Button; Accessible.name: root.resolvedCity ? root.resolvedCity.title : ""
        Accessible.description: qsTr("Потяните вверх или нажмите, чтобы открыть фото и подробности")
        Keys.onReturnPressed: root.revealDetails(); Keys.onEnterPressed: root.revealDetails()
        radius: 24; color: AmneziaStyle.mayakDay ? "#f7f8fb" : "#ed0b1120"; border.width: 1; border.color: AmneziaStyle.mayakDay ? "#dcd7cc" : "#343b50"
        ColumnLayout { id: cardColumn; anchors.fill: parent; anchors.margins: 18; spacing: 9
            Item { Layout.fillWidth: true; Layout.preferredHeight: 4
                Rectangle { anchors.centerIn: parent; width: 36; height: 4; radius: 2; color: AmneziaStyle.mayakDay ? "#9A9FAB" : "#5E6880" }
            }
            Text { text: "●  СОЕДИНЕНИЕ ПРОВЕРЕНО"; color: AmneziaStyle.semanticPalette.ok; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 14; font.weight: Font.DemiBold }
            Text { id: cardTitle; objectName: "mayak-city-title"; Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.title : ""; color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 25; font.weight: Font.DemiBold; wrapMode: Text.WordWrap }
            Text { Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.shortText : ""; color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 17; wrapMode: Text.WordWrap }
            Text { objectName: "mayak-city-gesture-hint"; Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "⌃  Потяните вверх: фото и подробности"; color: AmneziaStyle.mayakDay ? AmneziaStyle.semanticPalette.beamStrong : AmneziaStyle.color.mayakBeam; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 15; font.weight: Font.DemiBold }
        }
        MouseArea {
            objectName: "mayak-city-card-input"
            anchors.fill: parent
            enabled: root.detailsProgress < 0.5 || root.detailDragActive
            preventStealing: true
            property real startY: 0
            property real startProgress: 0
            property bool dragged: false
            function settleCollapsed() {
                // Clear the grab latch first so disabling this handler cannot
                // recursively settle a cancellation for the same pointer.
                root.detailDragActive = false
                root.cityDetailsOpen = false
                detailProgressAnimation.stop()
                detailProgressAnimation.from = root.detailsProgress
                detailProgressAnimation.to = 0
                detailProgressAnimation.duration = AmneziaStyle.mayakReduceMotion ? 0 : 260
                detailProgressAnimation.start()
            }
            onPressed: function(mouse) { startY = mouse.y; startProgress = root.detailsProgress; dragged = false; root.collapsedTitleY = cardTitle.mapToItem(root, 0, 0).y; root.collapsedTitleX = cardTitle.mapToItem(root, 0, 0).x; root.collapsedTitleWidth = cardTitle.width; root.detailDragActive = true; detailProgressAnimation.stop() }
            onPositionChanged: function(mouse) {
                const delta = mouse.y - startY
                if (Math.abs(delta) > 8) dragged = true
                if (dragged) root.detailsProgress = Math.max(0, Math.min(1, startProgress + (-delta / 180)))
            }
            onReleased: function(mouse) {
                if (dragged && startY - mouse.y > 36) root.revealDetails()
                else if (dragged) settleCollapsed()
                root.detailDragActive = false
            }
            onCanceled: if (root.detailDragActive) settleCollapsed()
            onClicked: if (!dragged) root.revealDetails()
        }
    }

    // Idle/waiting keeps its original layout reservation. Connected uses the
    // measured header-to-card box, which is unchanged throughout the overlay.
    ConnectButton {
        id: connectButton; objectName: "mayak-main-connect"
        z: 1
        x: (root.width - width) / 2
        y: root.cityVisible ? root.connectedActionTop + Math.max(0, (root.connectedActionHeight - height) / 2)
                            : 18 + PageController.safeAreaTopMargin + 48 + 8 + root.heroTopGap
        width: root.cityVisible ? Math.min(470, root.width - 36)
                                : Math.min(Math.max(204, root.beaconDiameter), root.width - 36)
        height: Math.max(48, implicitHeight)
        exitLocation: root.exitLocation
        citySceneActive: root.cityVisible
        beaconDiameter: root.beaconDiameter
        opacity: 1 - root.detailsProgress
        enabled: root.detailsProgress < 0.5
        Accessible.ignored: root.detailsProgress > 0.95
        text: archivePhase === "CleanupPending" ? qsTr("Повторить отключение") : archivePhase === "Stopping" ? qsTr("Отключаем…") : ["Fetching", "Admitting", "Starting", "Verifying"].indexOf(archivePhase) >= 0 || (archivePhase === "Idle" && inProgress) ? qsTr("Подключаем…") : archivePhase === "Preparing" ? ConnectionController.connectionStateText : connected ? qsTr("Выключить Маяк") : qsTr("Включить Маяк")
        Accessible.name: text; Accessible.description: ConnectionController.connectionStateText
        KeyNavigation.tab: cancelButton
    }
    Rectangle {
        id: cityDetails; objectName: "mayak-city-details"
        anchors.fill: parent
        z: 2
        color: "transparent"
        visible: root.cityVisible && (root.cityDetailsOpen || root.detailsProgress > 0.001)
        opacity: Math.min(1, 2 * root.detailsProgress)
        Flickable {
            id: detailsScroll; objectName: "mayak-details-scroll"
            anchors.left: parent.left; anchors.right: parent.right
            anchors.top: parent.top; anchors.bottom: parent.bottom
            anchors.topMargin: root.detailsTopY; anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
            clip: true; contentWidth: width; contentHeight: detailsContent.implicitHeight
            interactive: root.cityDetailsOpen
            boundsBehavior: Flickable.DragAndOvershootBounds
            Rectangle {
                id: readingScrim
                objectName: "mayak-details-read-scrim"
                x: 0; y: Math.max(0, root.collapsedTitleY - root.detailsTopY - 120)
                width: detailsScroll.width
                height: Math.max(0, detailsContent.implicitHeight - y)
                z: -1
                gradient: Gradient {
                    GradientStop { position: 0.0; color: AmneziaStyle.mayakDay ? "#00F5F3EE" : "#000A0F1C" }
                    GradientStop { position: Math.min(1, 70 / Math.max(120, readingScrim.height)); color: AmneziaStyle.mayakDay ? "#99F5F3EE" : "#990A0F1C" }
                    GradientStop { position: Math.min(1, 120 / Math.max(120, readingScrim.height)); color: AmneziaStyle.color.mayakSurface0 }
                    GradientStop { position: 1.0; color: AmneziaStyle.color.mayakSurface0 }
                }
            }
            ColumnLayout { id: detailsContent; x: (detailsScroll.width - width) / 2; width: Math.min(520, Math.max(0, detailsScroll.width - 36)); spacing: 14
                Item {
                    objectName: "mayak-details-title-spacer"
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.max(0, root.collapsedTitleY - root.detailsTopY - detailsContent.spacing)
                }
                Item {
                    Layout.fillWidth: true
                    implicitHeight: detailsCityTitle.implicitHeight
                    Text { id: detailsCityTitle; objectName: "mayak-details-city-title"; x: Math.max(0, root.collapsedTitleX - detailsContent.x); width: Math.min(Math.max(0, parent.width - x), root.collapsedTitleWidth > 0 ? root.collapsedTitleWidth : parent.width); text: root.resolvedCity ? root.resolvedCity.title : ""; color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 25; font.weight: Font.DemiBold; wrapMode: Text.WordWrap }
                }
                Text { objectName: "mayak-details-city-short"; opacity: root.detailsBodyOpacity; Layout.fillWidth: true; text: root.resolvedCity ? root.resolvedCity.shortText : ""; color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 17; wrapMode: Text.WordWrap }
                Repeater { objectName: "mayak-city-paragraphs"; model: root.resolvedCity ? root.resolvedCity.paragraphs : []; delegate: Text { opacity: root.detailsBodyOpacity; Layout.fillWidth: true; text: modelData; wrapMode: Text.WordWrap; lineHeight: 1.5; color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 16 } }
                Text { opacity: root.detailsBodyOpacity; text: qsTr("Что посмотреть"); color: AmneziaStyle.color.mayakInk; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 20; font.weight: Font.DemiBold }
                Repeater { objectName: "mayak-city-sights"; model: root.resolvedCity ? root.resolvedCity.sights : []; delegate: ColumnLayout { opacity: root.detailsBodyOpacity; Layout.fillWidth: true; spacing: 2; Text { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: modelData[0]; color: AmneziaStyle.mayakDay ? AmneziaStyle.semanticPalette.beamStrong : AmneziaStyle.color.mayakBeam; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 16; font.weight: Font.DemiBold } Text { Layout.fillWidth: true; text: modelData[1]; color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 15; wrapMode: Text.WordWrap } } }
                Text { objectName: "mayak-city-photo-credit"; opacity: root.detailsBodyOpacity; Layout.fillWidth: true; text: root.resolvedCity ? qsTr("Фото: %1, «%2», %3 · %4 (%5). Source: %6.").arg(root.resolvedCity.author).arg(root.resolvedCity.photoTitle).arg(root.resolvedCity.license).arg(root.resolvedCity.licenseUrl).arg(root.resolvedCity.source).arg(root.resolvedCity.sourceUrl) : ""; color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 13; wrapMode: Text.WordWrap }
                Text { opacity: root.detailsBodyOpacity; Layout.fillWidth: true; text: qsTr("Город выхода показан по данным сервера."); color: AmneziaStyle.color.mayakInkMuted; font.family: AmneziaStyle.uiFontFamily; font.pixelSize: 13; wrapMode: Text.WordWrap }
            }
        }
        Rectangle {
            anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
            height: 14 + PageController.safeAreaBottomMargin
            color: AmneziaStyle.color.mayakSurface0
        }
    }
    Item {
        objectName: "mayak-city-gesture-glass"
        z: 10
        anchors.left: parent.left; anchors.right: parent.right
        anchors.top: parent.top; anchors.bottom: parent.bottom
        anchors.topMargin: root.detailsTopY
        anchors.bottomMargin: 14 + PageController.safeAreaBottomMargin
        enabled: root.cityDetailsOpen && root.cityVisible
            PointHandler {
                target: null
                acceptedButtons: Qt.NoButton
                property bool beganAtTop: false
                property point startPosition
                onActiveChanged: {
                    if (active) {
                        beganAtTop = detailsScroll.contentY <= 1 && root.cityDetailsOpen
                        startPosition = point.scenePosition
                    } else {
                        beganAtTop = false
                    }
                }
                onPointChanged: {
                    if (!active || !beganAtTop || !root.cityDetailsOpen) return
                    const dy = point.scenePosition.y - startPosition.y
                    const dx = point.scenePosition.x - startPosition.x
                    if (dy > 36 && dy > Math.abs(dx)) {
                        beganAtTop = false
                        root.collapseDetails()
                    }
                }
                onCanceled: beganAtTop = false
            }
    }
    Keys.onEscapePressed: if (cityDetailsOpen) collapseDetails()
    Keys.onBackPressed: if (cityDetailsOpen) collapseDetails()
}
