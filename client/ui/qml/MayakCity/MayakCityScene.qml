import QtQuick

Item {
    id: root
    property string photoSource: ""
    property bool sceneActive: false
    property bool reduceMotion: false
    property real detailsScrollOffset: 0

    Image {
        id: photo
        objectName: "mayak-city-photo"
        anchors.left: parent.left
        anchors.right: parent.right
        y: -root.detailsScrollOffset
        height: parent.height + root.detailsScrollOffset
        source: root.sceneActive ? root.photoSource : ""
        fillMode: Image.PreserveAspectCrop
        asynchronous: true
        cache: true
        sourceSize.width: Math.ceil(root.width * 1.5)
        sourceSize.height: Math.ceil(root.height * 1.5)
        opacity: root.sceneActive ? 1 : 0
        scale: root.sceneActive ? 1 : 1.06
        Behavior on opacity { NumberAnimation { duration: root.reduceMotion ? 0 : 600 } }
        Behavior on scale { NumberAnimation { duration: root.reduceMotion ? 0 : 1200; easing.type: Easing.OutCubic } }
    }

    Rectangle {
        anchors.fill: parent
        z: 1
        visible: root.sceneActive
        gradient: Gradient {
            GradientStop { position: 0; color: "#a804070f" }
            GradientStop { position: 0.24; color: "#2204070f" }
            GradientStop { position: 0.58; color: "#0004070f" }
            GradientStop { position: 0.78; color: "#cc04070f" }
            GradientStop { position: 1; color: "#f204070f" }
        }
    }
}
