import QtQuick
import QtQuick.Controls

ApplicationWindow {
    visible: true
    width: PreviewPhoneSize ? 360 : 1280
    height: PreviewPhoneSize ? 720 : 850
    title: PreviewMode === "updates" ? "Маяк — mock updates" : "Маяк — mock invite flow"
    color: "#101820"
    Loader {
        anchors.fill: parent
        source: PreviewMode === "updates"
                ? "../../client/ui/qml/Pages2/PageUpdate.qml"
                : "../../client/ui/qml/Pages2/PageMayakInvite.qml"
        visible: !PageController.homeShown
    }
    Column {
        visible: PageController.homeShown
        anchors.centerIn: parent
        spacing: 18
        Label { anchors.horizontalCenter: parent.horizontalCenter; text: "Маяк VPN"; color: "#f4f7fa"; font.pixelSize: 28; font.bold: true }
        Label { anchors.horizontalCenter: parent.horizontalCenter; text: "Настройка завершена. Дальше — штатная кнопка подключения."; color: "#b7c3ce"; wrapMode: Text.WordWrap; width: 340; horizontalAlignment: Text.AlignHCenter }
    }
}
