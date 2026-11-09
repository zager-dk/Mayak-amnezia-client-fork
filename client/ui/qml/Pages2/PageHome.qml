import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Style 1.0
import "../Controls2"
import "../Controls2/TextTypes"
import "../Components"

PageType {
    id: root
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        anchors.topMargin: 24 + PageController.safeAreaTopMargin
        anchors.bottomMargin: 24 + PageController.safeAreaBottomMargin
        spacing: 20
        H2TextType {
            Layout.fillWidth: true
            text: qsTr("Маяк")
            horizontalAlignment: Text.AlignHCenter
        }
        BodyTextType {
            Layout.fillWidth: true
            text: qsTr("Свободный сервер выбирается автоматически")
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.textSecondary
        }
        Item { Layout.fillHeight: true }
        ConnectButton {
            objectName: "mayak-main-connect"
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: Math.min(220, root.width - 48)
            Layout.preferredHeight: Layout.preferredWidth
            text: inProgress ? qsTr("Подключаем…") : connected ? qsTr("Выключить Маяк") : qsTr("Включить Маяк")
        }
        BodyTextType {
            Layout.fillWidth: true
            text: ConnectionController.connectionStateText
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: AmneziaStyle.color.textSecondary
        }
        Item { Layout.fillHeight: true }
    }
}
