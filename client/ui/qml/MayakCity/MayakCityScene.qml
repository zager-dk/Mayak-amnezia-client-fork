import QtQuick

Item {
    id: root
    property string photoSource: ""
    property bool sceneActive: false
    property bool reduceMotion: false
    property real detailsScrollOffset: 0
    property real detailsProgress: 0
    property bool retainingPhoto: false
    // Veil over the photo so it does not fight the beacon: navy at night, warm white by day.
    // It lifts while the city description opens (detailsProgress 0 -> 1).
    property bool day: false
    property real veilStrength: 0.7   // owner chose 70% (09.11.2026)

    onSceneActiveChanged: {
        if (sceneActive) {
            retainingPhoto = true
            if (photo.source.toString() !== photoSource) photo.source = photoSource
        }
    }
    onPhotoSourceChanged: if (sceneActive && photoSource.length > 0 && photo.source.toString() !== photoSource) photo.source = photoSource

    Image {
        id: photo
        objectName: "mayak-city-photo"
        anchors.left: parent.left
        anchors.right: parent.right
        y: -root.detailsScrollOffset
        height: parent.height + root.detailsScrollOffset
        fillMode: Image.PreserveAspectCrop
        asynchronous: true
        cache: true
        sourceSize.width: Math.ceil(root.width * 1.5)
        sourceSize.height: Math.ceil(root.height * 1.5)
        opacity: root.sceneActive && status === Image.Ready ? 1 : 0
        scale: root.sceneActive && status === Image.Ready ? 1 : 1.06
        Behavior on opacity { NumberAnimation { duration: root.reduceMotion ? 0 : (root.sceneActive ? 600 : 350); easing.type: root.sceneActive ? Easing.OutCubic : Easing.InCubic } }
        Behavior on scale { NumberAnimation { duration: root.reduceMotion ? 0 : 1200; easing.type: Easing.OutCubic } }
        onOpacityChanged: {
            if (opacity <= 0.001 && !root.sceneActive) {
                Qt.callLater(function() {
                    if (!root.sceneActive && photo.opacity <= 0.001) {
                        photo.source = ""
                        root.retainingPhoto = false
                    }
                })
            }
        }
    }

    Rectangle {
        objectName: "mayak-city-photo-veil"
        anchors.fill: parent
        z: 0.5
        color: root.day ? "#F5F3EE" : "#0B1430"
        opacity: (root.sceneActive && photo.status === Image.Ready ? root.veilStrength : 0) * (1 - root.detailsProgress)
        Behavior on color { ColorAnimation { duration: 220 } }
    }

    Rectangle {
        anchors.fill: parent
        z: 1
        visible: root.sceneActive || opacity > 0.001
        opacity: root.sceneActive ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: root.reduceMotion ? 0 : (root.sceneActive ? 220 : 150) } }
        gradient: Gradient {
            GradientStop { position: 0; color: root.day ? "#b3f5f3ee" : "#a804070f" }
            GradientStop { position: 0.24; color: root.day ? "#22f5f3ee" : "#2204070f" }
            GradientStop { position: 0.58; color: root.day ? "#00f5f3ee" : "#0004070f" }
            GradientStop { position: 0.78; color: root.day ? Qt.rgba(245 / 255, 243 / 255, 238 / 255, 0.8 * (1 - root.detailsProgress)) : Qt.rgba(4 / 255, 7 / 255, 15 / 255, 0.8 * (1 - root.detailsProgress)) }
            GradientStop { position: 1; color: root.day ? Qt.rgba(245 / 255, 243 / 255, 238 / 255, 0.95 * (1 - root.detailsProgress)) : Qt.rgba(4 / 255, 7 / 255, 15 / 255, 0.95 * (1 - root.detailsProgress)) }
        }
    }
}
