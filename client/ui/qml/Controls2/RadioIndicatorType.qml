import QtQuick

import Style 1.0

Item {
    id: root

    property bool checked: false

    implicitWidth: 24
    implicitHeight: 24

    Rectangle {
        anchors.fill: parent
        anchors.margins: 0.5

        radius: width / 2
        color: root.checked ? AmneziaStyle.color.bgBase : AmneziaStyle.color.transparent
        border.width: 1
        border.color: root.checked ? AmneziaStyle.color.mayakInk : AmneziaStyle.color.mayakLineStrong

        Behavior on border.color {
            ColorAnimation { duration: 150 }
        }
    }

    // Mayak design system: selection is neutral (ink), no amber and no glow.
    Rectangle {
        id: dot

        anchors.centerIn: parent
        width: 12
        height: 12

        radius: 6
        color: AmneziaStyle.color.mayakInk
        visible: root.checked
    }
}
