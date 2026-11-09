// Archive MayakBeacon F7: original SVG layers, projected beam, contour and water reflections.
// Adapted only to genuine coarse controller booleans; all timing below is decorative.
import QtQuick
import QtQuick.Shapes
import QtQuick.Effects
import QtQuick.Window

Item {
    id: root

    // ---- входы ----
    // Archive F7 artwork/motion driven by the accepted read-only coordinator phase.
    property string phase: "Idle"
    readonly property bool motionActive: isConnecting(phase) && active && !reduceMotion
    Accessible.ignored: true
    property bool reduceMotion: false
    // false, когда окно свёрнуто или приложение в фоне: вращение на паузе, угол сохраняется
    property bool active: true
    // Day theme: the same scene as a black-and-white inversion; amber stays amber.
    property bool day: false
    property url skySource: day ? "assets/f7-layer-sky-day.svg" : "assets/f7-layer-sky.svg"
    property url landTowerSource: day ? "assets/f7-layer-land-tower-day.svg" : "assets/f7-layer-land-tower.svg"
    // Layers are rendered at the real on-screen pixel size (no upscaled textures).
    readonly property size layerPixels: Qt.size(Math.ceil(width * Screen.devicePixelRatio), Math.ceil(height * Screen.devicePixelRatio))

    // ---- выходы ----
    // Луч встал вправо после Connected: можно показывать фото города и карточку.
    signal beamSettled()

    implicitWidth: 240
    implicitHeight: 240

    // ---- параметры характера «Быстрый» ----
    readonly property real spinDeg: 170
    readonly property real spinVerifyDeg: 110
    readonly property int  dir: -1          // направление вращения
    readonly property real igniteSec: 0.25
    readonly property real lockSec: 0.6
    readonly property real extinguishSec: 0.3

    // ---- внутреннее состояние анимации ----
    property real lit: 0                    // 0..1 — насколько горит фонарь
    property real theta: 0                  // угол луча вокруг вертикальной оси, рад; 0 = вправо
    property real speed: 0                  // °/с, текущая
    property real targetSpeed: 0            // °/с, целевая
    property real dangerK: 0                // 0..1 — переход контура в красный
    property string tone: "normal"          // normal | danger | warn
    property bool locking: false
    property real lockFrom: 0
    property real lockTo: 0
    property real lockT: 0
    property bool pulsing: false            // режим «уменьшить движение»
    property real pulseT: 0
    property real pulsePeriod: 1.6
    property real pulseLo: 0.4
    property real pulseHi: 1
    property real litFrom: 0
    property real litTo: 0
    property real litT: 1
    property real litDur: 0.25
    property int  litCurve: 0               // 0 ease-out, 1 ease-in, 2 linear
    property real failT: -1
    property real failFrom: 1
    property real clock: 0

    function isConnecting(p) { return p === "Fetching" || p === "Admitting" || p === "Starting" || p === "Verifying" }
    readonly property bool connecting: isConnecting(phase)
    readonly property real beamLen: 140 * Math.min(1, lit * 1.15)
    readonly property real trail: reduceMotion ? 0 : Math.min(1, Math.abs(speed) / spinDeg)

    // ---- помощники ----
    function clamp01(v) { return Math.max(0, Math.min(1, v)) }
    function smooth(e0, e1, x) { var t = clamp01((x - e0) / (e1 - e0)); return t * t * (3 - 2 * t) }
    function mix(a, b, t) { return Qt.rgba(a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t, a.b + (b.b - a.b) * t, 1) }
    function animateLit(to, sec, curve) { litFrom = lit; litTo = to; litT = 0; litDur = Math.max(0.001, sec); litCurve = curve }
    function startPulse(period, lo, hi) { pulsing = true; pulsePeriod = period; pulseLo = lo; pulseHi = hi; pulseT = 0 }

    // Проекция луча, повёрнутого вокруг вертикальной оси, на вид сбоку (единицы 240×240).
    function geom(th, L) {
        var c = Math.cos(th), s = Math.sin(th), dx = c * L, adx = Math.abs(dx), persp = 1 + 0.5 * s
        return { c: c, s: s, yc: 73 - 0.12 * adx,
                 hw: (6 + 30 * Math.abs(c)) * persp, hc: (2 + 12 * Math.abs(c)) * persp,
                 ex: 118 + (adx < 1 ? (dx < 0 ? -1 : 1) : dx) }
    }
    function intensity(th, litv) {
        var c = Math.cos(th), s = Math.sin(th)
        return litv * (0.3 + 0.7 * Math.abs(c)) * (0.75 + 0.25 * s)
    }
    function frontShare(th) { return smooth(-0.15, 0.15, Math.sin(th)) }
    function flashOf(th, litv) { return litv * Math.pow(Math.max(0, Math.sin(th)), 6) }

    // ---- phase-driven archive motion; state transitions always come from the controller ----
    function updatePresentation() {
        tone = "normal"
        pulsing = false
        failT = -1
        if (isConnecting(phase)) {
            if (phase === "Fetching") animateLit(1, igniteSec, 0)
            locking = false
            targetSpeed = reduceMotion ? 0 : (phase === "Verifying" ? spinVerifyDeg : spinDeg)
            if (reduceMotion) {
                theta = 0; speed = 0
                startPulse(phase === "Verifying" ? 1.0 : 1.6, 0.4, 1)
            }
        } else if (phase === "Connected") {
            targetSpeed = 0; animateLit(1, 0.15, 0)
            if (reduceMotion) { theta = 0; speed = 0; beamSettled() }
            else {
                var deg = theta * 180 / Math.PI
                lockFrom = theta
                lockTo = (dir < 0 ? Math.floor((deg - 90) / 360) : Math.ceil((deg + 90) / 360)) * 2 * Math.PI
                lockT = 0; locking = true
            }
        } else if (phase === "Stopping") {
            locking = false; targetSpeed = 0; animateLit(0, extinguishSec, 1)
        } else if (phase === "Failed") {
            tone = "danger"; dangerK = 0; locking = false; targetSpeed = 0; litT = 1
            if (reduceMotion) animateLit(0, 0.7, 2)
            else { failT = 0; failFrom = Math.max(0.6, lit) }
        } else if (phase === "CleanupPending") {
            tone = "warn"; targetSpeed = 0; locking = false
            if (reduceMotion) { litT = 1; startPulse(2.4, 0.1, 0.35) }
            else animateLit(0.25, 0.3, 0)
        } else {
            // Preparing is a truthful pre-coordinator state: no Fetching ignition or spinner.
            // Idle and Cancelled settle with the same archive extinguish behavior.
            locking = false; targetSpeed = 0
            if (reduceMotion) { theta = 0; speed = 0 }
            if (lit > 0.01) animateLit(0, extinguishSec, 1)
        }
    }
    onPhaseChanged: updatePresentation()
    onReduceMotionChanged: updatePresentation()
    Component.onCompleted: updatePresentation()

    function step(dt) {
        clock += dt
        if (locking) {
            lockT = Math.min(1, lockT + dt / lockSec)
            var e = 1 - Math.pow(1 - lockT, 2)
            theta = lockFrom + (lockTo - lockFrom) * e
            if (lockT >= 1) { locking = false; theta = 0; speed = 0; beamSettled() }
        } else {
            speed += (targetSpeed - speed) * Math.min(1, dt * 2.4)
            var t = theta + dir * speed * Math.PI / 180 * dt
            if (t < 0) t += 2 * Math.PI
            if (t > 2 * Math.PI) t -= 2 * Math.PI
            theta = t
        }
        if (litT < 1) {
            litT = Math.min(1, litT + dt / litDur)
            var p = litT, k = litCurve === 0 ? 1 - (1 - p) * (1 - p) : (litCurve === 1 ? p * p : p)
            lit = litFrom + (litTo - litFrom) * k
        } else if (pulsing) {
            pulseT += dt
            lit = pulseLo + (pulseHi - pulseLo) * (0.5 + 0.5 * Math.cos(2 * Math.PI * pulseT / pulsePeriod))
        }
        if (failT >= 0) {
            failT += dt
            var seq = [1, 0.15, 0.85, 0.05, 0.5, 0]
            lit = seq[Math.min(5, Math.floor(failT / 0.15))] * failFrom
            if (failT > 0.9) { failT = -1; lit = 0 }
        }
        dangerK = tone === "danger" ? Math.min(1, dangerK + dt / 0.3) : 0
    }

    FrameAnimation {
        running: root.visible && root.active
        onTriggered: root.step(Math.min(0.05, frameTime))
    }

    // ---- цвета ----
    readonly property color rimOff: day ? "#565e70" : "#9cc2ff"   // day: ink-muted, same as the checked switch
    readonly property color rimOn: "#ffc54d"
    readonly property color danger: "#ff7b7b"
    readonly property color warn: "#f7a35e"
    readonly property color rimColor: tone === "danger" ? mix(rimOff, danger, dangerK)
                                     : tone === "warn" ? warn : mix(rimOff, rimOn, clamp01(lit))
    property color ringOffColor: "#5a6890"          // дневная тема: "#8f887a"
    readonly property color ringColor: tone === "danger" ? mix(ringOffColor, danger, dangerK)
                                      : tone === "warn" ? warn
                                      : (lit > 0.02 ? mix(ringOffColor, rimOn, clamp01(lit)) : ringOffColor)
    readonly property real flash: Math.max(flashOf(theta, lit), flashOf(theta + Math.PI, lit * 0.2))

    // ---- один слой луча: треугольник от фонаря с градиентом вдоль луча ----
    component BeamShape: Shape {
        id: bs
        property real th: 0
        property real len: 140
        property real alpha: 0
        property bool core: false
        readonly property var g: root.geom(th, len)
        readonly property real half: core ? g.hc : g.hw
        anchors.fill: parent
        opacity: Math.max(0, alpha)
        // Не привязывать visible к opacity: Shape, созданный невидимым, может не пересчитать геометрию.
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
            strokeColor: "transparent"
            fillGradient: LinearGradient {
                x1: 118; y1: 73; x2: bs.g.ex; y2: bs.g.yc
                GradientStop { position: 0; color: bs.core ? Qt.rgba(1, 0.94, 0.78, 0.95) : Qt.rgba(1, 0.82, 0.48, 0.8) }
                GradientStop { position: bs.core ? 1 : 0.55; color: bs.core ? Qt.rgba(1, 0.82, 0.48, 0) : Qt.rgba(1, 0.77, 0.30, 0.22) }
                GradientStop { position: 1; color: Qt.rgba(1, 0.77, 0.30, 0) }
            }
            PathPolyline { path: [ Qt.point(118, 73), Qt.point(bs.g.ex, bs.g.yc - bs.half), Qt.point(bs.g.ex, bs.g.yc + bs.half), Qt.point(118, 73) ] }
        }
    }

    // ---- мягкий круг (ореол фонаря и вспышка) ----
    component GlowDisc: Shape {
        id: gd
        property real r: 34
        property color inner: "#ffd27a"
        property real innerAlpha: 0.75
        anchors.fill: parent
        ShapePath {
            strokeColor: "transparent"
            fillGradient: RadialGradient {
                centerX: 118; centerY: 73; centerRadius: gd.r; focalX: 118; focalY: 73
                GradientStop { position: 0; color: Qt.rgba(gd.inner.r, gd.inner.g, gd.inner.b, gd.innerAlpha) }
                GradientStop { position: 0.35; color: Qt.rgba(1, 0.77, 0.30, 0.22) }
                GradientStop { position: 1; color: Qt.rgba(1, 0.77, 0.30, 0) }
            }
            PathAngleArc { centerX: 118; centerY: 73; radiusX: gd.r; radiusY: gd.r; startAngle: 0; sweepAngle: 360 }
        }
    }

    // ---- сцена 240×240, масштабируется под размер кнопки ----
    Item {
        id: sceneWrap
        anchors.fill: parent
        layer.enabled: true
        layer.textureSize: root.layerPixels
        layer.samples: 4            // MSAA: smooth tower contour and beam edges
        layer.smooth: true
        visible: false

        Item {
            id: scene
            width: 240; height: 240
            scale: root.width / 240
            transformOrigin: Item.TopLeft

            Image { anchors.fill: parent; source: root.skySource; sourceSize: Qt.size(root.width * 2, root.height * 2); smooth: true }

            // лучи за башней: дымка (сильное размытие) и ядро (слабое)
            Item {
                id: hazeBack; anchors.fill: parent; layer.enabled: true; layer.textureSize: root.layerPixels; layer.smooth: true; visible: false
                BeamShape { th: root.theta; len: root.beamLen; alpha: root.intensity(root.theta, root.lit) * (1 - root.frontShare(root.theta)) * 0.6 }
                BeamShape { th: root.theta + Math.PI; len: root.beamLen * 0.75; alpha: root.intensity(root.theta + Math.PI, root.lit * 0.2) * (1 - root.frontShare(root.theta + Math.PI)) * 0.6 }
                BeamShape { th: root.theta - root.dir * 0.26; len: root.beamLen * 0.95; alpha: root.intensity(root.theta, root.lit) * root.trail * 0.45 }
                BeamShape { th: root.theta - root.dir * 0.52; len: root.beamLen * 0.87; alpha: root.intensity(root.theta, root.lit) * root.trail * 0.22 }
            }
            MultiEffect { source: hazeBack; anchors.fill: hazeBack; blurEnabled: true; blur: 1.0; blurMax: 20 }
            Item {
                id: coreBack; anchors.fill: parent; layer.enabled: true; layer.textureSize: root.layerPixels; layer.smooth: true; visible: false
                BeamShape { core: true; th: root.theta; len: root.beamLen; alpha: root.intensity(root.theta, root.lit) * (1 - root.frontShare(root.theta)) * 0.6 * 0.85 }
            }
            MultiEffect { source: coreBack; anchors.fill: coreBack; blurEnabled: true; blur: 0.35; blurMax: 8 }

            GlowDisc { r: 34; opacity: root.lit * 0.9 }

            Image { anchors.fill: parent; source: root.landTowerSource; sourceSize: Qt.size(root.width * 2, root.height * 2); smooth: true }

            // фонарь
            Rectangle {
                id: lantern
                x: 109; y: 64; width: 18; height: 19; radius: 2; clip: true
                color: root.flash > 0.05 ? root.mix(Qt.color("#ffd27a"), Qt.color("#fff6dc"), root.flash * 0.8)
                                         : root.mix(Qt.color(root.day ? "#dde2ea" : "#1a2034"), Qt.color("#ffd27a"), root.clamp01(root.lit))
                Rectangle { x: 6; width: 1.4; height: parent.height; color: root.mix(Qt.color(root.day ? "#a6aebd" : "#0a0f1c"), Qt.color("#d99a22"), root.clamp01(root.lit)) }
                Rectangle { x: 12; width: 1.4; height: parent.height; color: root.mix(Qt.color(root.day ? "#a6aebd" : "#0a0f1c"), Qt.color("#d99a22"), root.clamp01(root.lit)) }
                // блик вращающейся линзы
                Rectangle { x: 7 + 7 * Math.cos(root.theta); width: 4; height: parent.height; color: "#fff6dc"
                            opacity: root.reduceMotion ? 0 : root.lit * Math.max(0, Math.sin(root.theta)) * 0.9 }
                Rectangle { x: 7 + 7 * Math.cos(root.theta + Math.PI); width: 4; height: parent.height; color: "#fff6dc"
                            opacity: root.reduceMotion ? 0 : root.lit * 0.5 * Math.max(0, Math.sin(root.theta + Math.PI)) * 0.9 }
            }

            // контур: голубой без света, тёплый когда горит (днём — тёмный тёплый серый)
            Shape {
                anchors.fill: parent
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: root.rimColor; strokeWidth: 2.2; fillColor: "transparent"
                    capStyle: ShapePath.RoundCap; joinStyle: ShapePath.RoundJoin
                    PathSvg { path: "M125.5 88 L132 156 M133 83.5 H126 M130 64 A12 10 0 0 0 121 54.6 M127 65.5 V81.5" }
                }
                ShapePath {
                    strokeColor: Qt.rgba(root.rimColor.r, root.rimColor.g, root.rimColor.b, 0.45 - 0.15 * root.clamp01(root.lit))
                    strokeWidth: 1.3; fillColor: "transparent"
                    PathSvg { path: "M104 156 L110.5 88" }
                }
            }

            // лучи перед башней
            Item {
                id: hazeFront; anchors.fill: parent; layer.enabled: true; layer.textureSize: root.layerPixels; layer.smooth: true; visible: false
                BeamShape { th: root.theta; len: root.beamLen; alpha: root.intensity(root.theta, root.lit) * root.frontShare(root.theta) }
                BeamShape { th: root.theta + Math.PI; len: root.beamLen * 0.75; alpha: root.intensity(root.theta + Math.PI, root.lit * 0.2) * root.frontShare(root.theta + Math.PI) }
            }
            MultiEffect { source: hazeFront; anchors.fill: hazeFront; blurEnabled: true; blur: 1.0; blurMax: 20 }
            Item {
                id: coreFront; anchors.fill: parent; layer.enabled: true; layer.textureSize: root.layerPixels; layer.smooth: true; visible: false
                BeamShape { core: true; th: root.theta; len: root.beamLen; alpha: root.intensity(root.theta, root.lit) * root.frontShare(root.theta) * 0.85 }
            }
            MultiEffect { source: coreFront; anchors.fill: coreFront; blurEnabled: true; blur: 0.35; blurMax: 8 }

            // вспышка, когда луч смотрит на зрителя
            GlowDisc { r: 24 + 44 * root.flash; inner: "#fff6dc"; innerAlpha: 1; opacity: root.flash * 0.9 }

            // блики на воде — со стороны луча
            Item {
                anchors.fill: parent
                opacity: root.lit * Math.abs(Math.cos(root.theta)) * (Math.cos(root.theta) < 0 ? 0.6 : 1)
                transform: Scale { origin.x: 120; xScale: Math.cos(root.theta) < 0 ? -1 : 1 }
                Rectangle { x: 168; y: 186; width: 44; height: 1.5; radius: 0.75; color: "#ffc54d"; opacity: 0.45 }
                Rectangle { x: 178; y: 194; width: 30; height: 1.5; radius: 0.75; color: "#ffc54d"; opacity: 0.32 }
                Rectangle { x: 172; y: 203; width: 36; height: 1.5; radius: 0.75; color: "#ffc54d"; opacity: 0.22 }
                Rectangle { x: 186; y: 213; width: 20; height: 1.5; radius: 0.75; color: "#ffc54d"; opacity: 0.15 }
            }
        }
    }

    // круглая маска сцены
    Rectangle { id: discMask; anchors.fill: parent; radius: width / 2; visible: false; antialiasing: true
                layer.enabled: true; layer.textureSize: root.layerPixels; layer.smooth: true }
    // Soft threshold: the antialiased mask edge stays antialiased (no stair-stepping on the circle).
    MultiEffect { source: sceneWrap; anchors.fill: parent; maskEnabled: true; maskSource: discMask
                  maskThresholdMin: 0.5; maskSpreadAtMin: 1.0 }

    // кольцо кнопки
    Rectangle {
        anchors.fill: parent; radius: width / 2; color: "transparent"; antialiasing: true
        border.width: Math.max(1, 1.5 * root.width / 240); border.color: root.ringColor
    }
}

