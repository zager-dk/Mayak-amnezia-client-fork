import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Config"

PageType {
    id: root

    property bool isAppSplitTinnelingEnabled: Qt.platform.os === "windows" || Qt.platform.os === "android"

    FlickableType {
        id: flickable

        anchors.top: parent.top

        contentHeight: content.implicitHeight

        ColumnLayout {
            id: content

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right

            spacing: 0

            NavigationBarType {
                Layout.fillWidth: true

                title: qsTr("Connection")
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24 + PageController.safeAreaBottomMargin

                spacing: 0

                // Mayak 5.1.0.21: how Mayak reaches the server. Applies from the next connect.
                Text {
                    Layout.fillWidth: true
                    Layout.topMargin: 8
                    Layout.bottomMargin: 4
                    text: qsTr("Способ подключения")
                    color: AmneziaStyle.color.mayakInk
                    font.family: AmneziaStyle.uiFontFamily
                    font.pixelSize: 16
                    font.weight: Font.DemiBold
                    wrapMode: Text.WordWrap
                }
                Repeater {
                    model: [
                        { method: "auto", title: qsTr("Автоматически"),
                          subtitle: qsTr("Сначала AWG, если он не проходит — Xray. Рекомендуется") },
                        { method: "awg", title: qsTr("Только AWG"),
                          subtitle: qsTr("Самый быстрый способ, но в некоторых сетях не работает") },
                        { method: "xray", title: qsTr("Только Xray"),
                          subtitle: Qt.platform.os === "windows"
                                    ? qsTr("Медленнее AWG. Исключения программ на Windows не действуют")
                                    : qsTr("Медленнее AWG, но проходит там, где AWG не работает") }
                    ]
                    delegate: ListItemType {
                        required property var modelData
                        Layout.fillWidth: true
                        objectName: "mayak-connection-method-" + modelData.method
                        text: modelData.title
                        subtitle: modelData.subtitle
                        trailingIconSource: MayakRouting.connectionMethod === modelData.method ? "qrc:/images/controls/check.svg" : ""
                        Accessible.name: modelData.title + (MayakRouting.connectionMethod === modelData.method ? qsTr(", выбрано") : "")
                        onClicked: MayakRouting.connectionMethod = modelData.method
                    }
                }
                Text {
                    Layout.fillWidth: true
                    Layout.bottomMargin: 12
                    text: qsTr("Новый способ применится при следующем подключении.")
                    color: AmneziaStyle.color.mayakInk
                    opacity: 0.7
                    font.family: AmneziaStyle.uiFontFamily
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }

                ListItemType {
                    id: amneziaDnsRow

                    Layout.fillWidth: true

                    text: qsTr("Use AmneziaDNS")
                    subtitle: qsTr("If AmneziaDNS is installed on the server")

                    onClicked: {
                        amneziaDnsSwitch.toggle()
                        amneziaDnsSwitch.toggled()
                    }

                    SwitchType {
                        id: amneziaDnsSwitch

                        focusPolicy: Qt.NoFocus

                        checked: SettingsController.isAmneziaDnsEnabled()
                        onToggled: function() {
                            if (checked !== SettingsController.isAmneziaDnsEnabled()) {
                                SettingsController.toggleAmneziaDns(checked)
                            }
                        }
                    }
                }

                ListItemType {
                    id: dnsServersButton

                    Layout.fillWidth: true

                    text: qsTr("DNS servers")
                    subtitle: qsTr("When AmneziaDNS is not used or installed")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsDns)
                    }
                }

                ListItemType {
                    id: splitTunnelingButton

                    Layout.fillWidth: true

                    text: qsTr("Site-based split tunneling")
                    subtitle: qsTr("Allows you to select which sites you want to access through the VPN")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsSplitTunneling)
                    }
                }

                ListItemType {
                    id: splitTunnelingButton2

                    Layout.fillWidth: true

                    visible: root.isAppSplitTinnelingEnabled

                    text: qsTr("App-based split tunneling")
                    subtitle: qsTr("Allows you to use the VPN only for certain Apps")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsAppSplitTunneling)
                    }
                }

                ListItemType {
                    id: killSwitchButton

                    Layout.fillWidth: true

                    visible: !GC.isMobile()

                    text: qsTr("KillSwitch")
                    subtitle: qsTr("Blocks network connections without VPN")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsKillSwitch)
                    }
                }
            }
        }
    }
}
