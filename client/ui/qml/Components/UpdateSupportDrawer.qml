import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Style 1.0

import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"

SheetType {
    id: root

    expandedHeight: content.implicitHeight + 16 + PageController.safeAreaBottomMargin

    Item {
        id: contentRoot
        anchors.fill: parent

        ColumnLayout {
            id: content

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: 12
            spacing: 0

            SectionHeaderType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 32

                headerText: qsTr("Помощь с обновлением")
                descriptionText: qsTr("Если обновление не устанавливается, скачайте новую версию на сайте Маяка и установите её поверх.")
            }

            ListItemType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                showSeparator: false
                text: qsTr("Сайт Маяка")
                subtitle: qsTr("mayaklight.ru · скачать вручную")
                icon.source: "qrc:/images/controls/globe-2.svg"
                trailingIconSource: "qrc:/images/controls/external-link.svg"

                onClicked: {
                    Qt.openUrlExternally(LanguageUiController.getCurrentSiteUrl(""))
                }
            }
        }
    }
}
