import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Config"
import "../Controls2/TextTypes"
import "../Components"

PageType {
    id: root

    Connections {
        target: UpdateController

        function onUpdateNotFound() {
            PageController.showNotificationMessage(qsTr("You have the latest version of Mayak VPN"))
        }

        function onUpdateCheckFailed() {
            PageController.showNotificationMessage(qsTr("Failed to check for updates"))
        }
    }

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
            }

            Image {
                id: image

                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: 153
                Layout.preferredHeight: 131

                source: "qrc:/images/mayak-mark-round-128.png"
                sourceSize: Qt.size(153 * Screen.devicePixelRatio, 131 * Screen.devicePixelRatio)
                fillMode: Image.PreserveAspectFit
            }

            H1TextType {
                Layout.fillWidth: true
                Layout.topMargin: 12
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                horizontalAlignment: Text.AlignHCenter
                text: qsTr("Маяк VPN")
            }

            BodyTextType {
                Layout.fillWidth: true
                Layout.topMargin: 8
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                color: AmneziaStyle.color.textSecondary
                text: qsTr("Видно далеко. Приложение с открытым исходным кодом, основано на AmneziaVPN (GPLv3).")
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: 32
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24 + PageController.safeAreaBottomMargin

                spacing: 24

                ColumnLayout {
                    Layout.fillWidth: true

                    spacing: 12

                    BodyTextType {
                        Layout.fillWidth: true

                        color: AmneziaStyle.color.textTertiary
                        text: qsTr("Маяк в сети")
                    }

                    ColumnLayout {
                        Layout.fillWidth: true

                        spacing: 0

                        ListItemType {
                            Layout.fillWidth: true

                            text: qsTr("Сайт Маяка")
                            subtitle: qsTr("mayaklight.ru · загрузки и инструкции")
                            icon.source: "qrc:/images/controls/globe-2.svg"
                            trailingIconSource: "qrc:/images/controls/external-link.svg"

                            onClicked: Qt.openUrlExternally(LanguageUiController.getCurrentSiteUrl())
                        }

                        ListItemType {
                            Layout.fillWidth: true

                            text: qsTr("Личный кабинет")
                            subtitle: qsTr("Аккаунт, устройства и приглашения")
                            icon.source: "qrc:/images/controls/smartphone.svg"
                            trailingIconSource: "qrc:/images/controls/external-link.svg"

                            onClicked: Qt.openUrlExternally(LanguageUiController.getCurrentSiteUrl("my/"))
                        }

                        ListItemType {
                            Layout.fillWidth: true

                            text: qsTr("Исходный код")
                            subtitle: qsTr("Маяк на GitHub, лицензия GPLv3")
                            icon.source: "qrc:/images/controls/github.svg"
                            trailingIconSource: "qrc:/images/controls/external-link.svg"

                            onClicked: Qt.openUrlExternally("https://github.com/zager-dk/Mayak-amnezia-client-fork")
                        }
                    }
                }

                ColumnLayout {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.maximumWidth: content.width - 32

                    spacing: 12

                    RowLayout {
                        Layout.alignment: Qt.AlignHCenter

                        spacing: 4

                        CaptionTextType {
                            text: SettingsController.getAppVersion()
                            font.family: AmneziaStyle.monoFontFamily
                            font.pixelSize: 13

                            MouseArea {
                                property int clickCount: 0
                                anchors.fill: parent
                                onClicked: {
                                    if (clickCount > 10) {
                                        SettingsController.enableDevMode()
                                    } else {
                                        clickCount++
                                    }
                                }
                            }
                        }

                        IconButtonType {
                            size: IconButtonType.Small
                            icon.source: "qrc:/images/controls/copy.svg"
                            Accessible.name: qsTr("Copy version")

                            onClicked: {
                                GC.copyToClipBoard(SettingsController.getAppVersion())
                                PageController.showNotificationMessage(qsTr("Copied"))
                            }
                        }
                    }

                    ButtonType {
                        id: checkUpdatesButton

                        Layout.alignment: Qt.AlignHCenter
                        Layout.maximumWidth: content.width - 32

                        variant: ButtonType.Text
                        size: ButtonType.Medium
                        loading: UpdateController.isCheckRunning
                        enabled: UpdateController.isUpdateSupported && !UpdateController.isCheckRunning

                        text: UpdateController.isCheckRunning ? qsTr("Checking...") : qsTr("Check for updates")

                        onClicked: {
                            UpdateController.checkForUpdates()
                        }
                    }

                    BodyTextType {
                        Layout.fillWidth: true
                        visible: !UpdateController.isUpdateSupported
                        horizontalAlignment: Text.AlignHCenter
                        color: AmneziaStyle.color.textTertiary
                        text: qsTr("Для этой архитектуры устройства обновления недоступны.")
                    }

                    ButtonType {
                        id: privacyPolicyButton

                        Layout.alignment: Qt.AlignHCenter

                        variant: ButtonType.Text
                        size: ButtonType.Medium
                        text: qsTr("Политика конфиденциальности")

                        onClicked: {
                            Qt.openUrlExternally(LanguageUiController.getCurrentSiteUrl("privacy/"))
                        }
                    }
                }
            }
        }
    }
}
