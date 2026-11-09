import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import UpdateState 1.0
import Style 1.0
import "../Controls2"
import "../Controls2/TextTypes"

PageType {
    id: root
    isTabBarHidden: true
    NavigationBarType {
        id: navigationBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        title: qsTr("Обновление Маяка")
    }
    FlickableType {
        id: details
        anchors.top: navigationBar.bottom
        anchors.bottom: actions.top
        anchors.bottomMargin: 24
        contentHeight: content.implicitHeight + 24
        ColumnLayout {
            id: content
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.margins: 24
            spacing: 18
            H2TextType { Layout.fillWidth: true; text: qsTr("Маяк %1").arg(UpdateController.version) }
            BodyTextType {
                Layout.fillWidth: true
                text: UpdateController.description || qsTr("Улучшения подключения и работы приложения.")
                textFormat: Text.PlainText
                wrapMode: Text.WordWrap
            }
            BodyTextType {
                Layout.fillWidth: true
                text: qsTr("Обновление сохранит ваш вход и настройки. Подтвердите установку в системном окне. На Android установка закроет Маяк и его VPN-подключение.")
                wrapMode: Text.WordWrap
                color: AmneziaStyle.color.textSecondary
            }
        }
    }
    ColumnLayout {
        id: actions
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: 24
        anchors.rightMargin: 24
        anchors.bottomMargin: Math.max(48, PageController.safeAreaBottomMargin + 32)
        spacing: 16
        BodyTextType {
            objectName: "update-status"
            Layout.fillWidth: true
            visible: text.length > 0
            text: UpdateController.statusMessage
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.textPrimary
        }
        ProgressBarType {
            Layout.fillWidth: true
            visible: UpdateController.updateState === UpdateState.Downloading
            from: 0; to: 100; value: UpdateController.downloadProgress
            Accessible.name: qsTr("Загрузка обновления")
        }
        ButtonType {
            objectName: "update-install-button"
            Layout.fillWidth: true
            loading: UpdateController.updateState === UpdateState.Downloading
            enabled: UpdateController.isUpdateSupported && !loading
            text: UpdateController.updateState === UpdateState.ReadyToInstall ? qsTr("Установить обновление")
                : loading ? qsTr("Загружаем…") : UpdateController.updateState === UpdateState.DownloadError
                ? qsTr("Скачать ещё раз") : qsTr("Скачать обновление")
            onClicked: {
                if (UpdateController.updateState === UpdateState.ReadyToInstall) UpdateController.install()
                else if (UpdateController.updateState === UpdateState.DownloadError) UpdateController.retry()
                else UpdateController.update()
            }
        }
        ButtonType {
            Layout.fillWidth: true
            visible: UpdateController.updateState === UpdateState.Downloading
            variant: ButtonType.Text
            text: qsTr("Отменить загрузку")
            onClicked: UpdateController.cancel()
        }
    }
}
