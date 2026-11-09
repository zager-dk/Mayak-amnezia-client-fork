import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0

import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"

SheetType {
    id: root

    property bool isAppSplitTinnelingEnabled: Qt.platform.os === "windows" || Qt.platform.os === "android"
    readonly property bool russiaDirect: typeof MayakRouting !== "undefined" && MayakRouting.russiaDirect

    expandedHeight: Math.min(content.implicitHeight + 24 + PageController.safeAreaBottomMargin, windowHeight * 0.9)

    ColumnLayout {
        id: content

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: 0

        SectionHeaderType {
            Layout.fillWidth: true
            Layout.topMargin: 16
            Layout.rightMargin: 16
            Layout.leftMargin: 16
            Layout.bottomMargin: 32

            headerText: qsTr("Раздельное туннелирование")
            descriptionText: root.russiaDirect
                ? qsTr("Включён режим «Россия напрямую». Здесь — исключения: сайты и приложения, которые идут иначе.")
                : qsTr("Allows you to connect to some sites or applications through a VPN connection and bypass others")
        }

        ListItemType {
            id: splitTunnelingSwitch
            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16

            visible: ServersUiController.isDefaultServerDefaultContainerHasSplitTunneling

            text: qsTr("Split tunneling on the server")
            subtitle: qsTr("Enabled \nCan't be disabled for current server")
            trailingIconSource: "qrc:/images/controls/chevron-right.svg"

            onClicked: {
                root.close()
                PageController.goToPage(PageEnum.PageSettingsSplitTunneling)
            }
        }

        ListItemType {
            id: siteBasedSplitTunnelingSwitch
            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16

            text: root.russiaDirect ? qsTr("Исключения для сайтов") : qsTr("Site-based split tunneling")
            subtitle: root.russiaDirect ? qsTr("Всегда через VPN или всегда напрямую")
                                        : enabled && IpSplitTunnelingController.isSplitTunnelingEnabled ? qsTr("Enabled") : qsTr("Disabled")
            trailingIconSource: "qrc:/images/controls/chevron-right.svg"

            onClicked: {
                root.close()
                PageController.goToPage(PageEnum.PageSettingsSplitTunneling)
            }
        }

        ListItemType {
            id: appSplitTunnelingSwitch
            visible: isAppSplitTinnelingEnabled

            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16

            text: qsTr("App-based split tunneling")
            subtitle: AppSplitTunnelingController.isSplitTunnelingEnabled ? qsTr("Enabled") : qsTr("Disabled")
            trailingIconSource: "qrc:/images/controls/chevron-right.svg"

            onClicked: {
                root.close()
                PageController.goToPage(PageEnum.PageSettingsAppSplitTunneling)
            }
        }
    }
}
