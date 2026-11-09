pragma Singleton

import QtQuick
import QtCore

QtObject {
    property Settings appearanceSettings: Settings {
        category: "appearance"
        property bool day: false
        property bool reducedMotion: false
    }

    property bool mayakDay: appearanceSettings.day
    property bool mayakReduceMotion: appearanceSettings.reducedMotion
    onMayakDayChanged: appearanceSettings.day = mayakDay
    onMayakReduceMotionChanged: appearanceSettings.reducedMotion = mayakReduceMotion

    readonly property string uiFontFamily: onestFont.status === FontLoader.Ready ? onestFont.name : "PT Root UI VF"
    readonly property string monoFontFamily: monoFont.status === FontLoader.Ready ? monoFont.name : "monospace"
    property FontLoader onestFont: FontLoader { source: "qrc:/ui/qml/fonts/Onest.ttf" }
    property FontLoader monoFont: FontLoader { source: "qrc:/ui/qml/fonts/JetBrainsMono-Regular.ttf" }

    property QtObject semanticPalette: QtObject {
        readonly property color surface0: AmneziaStyle.mayakDay ? '#F5F3EE' : '#0A0F1C'
        readonly property color surface1: AmneziaStyle.mayakDay ? '#FFFFFF' : '#111827'
        readonly property color surface2: AmneziaStyle.mayakDay ? '#ECE9E2' : '#18213A'
        readonly property color surface3: AmneziaStyle.mayakDay ? '#E2DED5' : '#222D4A'
        readonly property color line: AmneziaStyle.mayakDay ? '#DCD7CC' : '#253150'
        readonly property color lineStrong: AmneziaStyle.mayakDay ? '#8F887A' : '#5A6890'
        readonly property color ink: AmneziaStyle.mayakDay ? '#131826' : '#ECEFF6'
        readonly property color muted: AmneziaStyle.mayakDay ? '#565E70' : '#9CA6BE'
        readonly property color beam: AmneziaStyle.mayakDay ? '#F2B12E' : '#FFC54D'
        readonly property color beamStrong: AmneziaStyle.mayakDay ? '#8A5B00' : '#FFD88A'
        readonly property color inkOnBeam: '#1B1405'
        readonly property color focus: AmneziaStyle.mayakDay ? '#2B5EA6' : '#8DB4F0'
        readonly property color ok: AmneziaStyle.mayakDay ? '#116B4A' : '#52D6A2'
        readonly property color warn: AmneziaStyle.mayakDay ? '#94500C' : '#F7A35E'
        readonly property color danger: AmneziaStyle.mayakDay ? '#BE3A30' : '#FF7B7B'
        readonly property color info: focus
    }

    property QtObject color: QtObject {
        readonly property color mayakSurface0: semanticPalette.surface0
        readonly property color mayakSurface1: semanticPalette.surface1
        readonly property color mayakSurface2: semanticPalette.surface2
        readonly property color mayakLine: semanticPalette.line
        readonly property color mayakLineStrong: semanticPalette.lineStrong
        readonly property color mayakInk: semanticPalette.ink
        readonly property color mayakInkMuted: semanticPalette.muted
        readonly property color mayakBeam: semanticPalette.beam
        readonly property color mayakFocus: semanticPalette.focus
        readonly property color transparent: 'transparent'

        readonly property color textPrimary: semanticPalette.ink
        readonly property color textSecondary: semanticPalette.muted
        readonly property color textTertiary: semanticPalette.muted
        readonly property color textQuaternary: semanticPalette.muted
        readonly property color textInverted: semanticPalette.inkOnBeam
        readonly property color textAccent: semanticPalette.beamStrong
        readonly property color textInfoInverse: semanticPalette.info
        readonly property color textStaticWhite: '#FFFFFF'

        readonly property color bgBase: semanticPalette.surface0
        readonly property color bgSurface: semanticPalette.surface1
        readonly property color bgSurfaceAlt: semanticPalette.surface2
        readonly property color bgSheet: semanticPalette.surface1
        readonly property color bgPanel: semanticPalette.surface2
        readonly property color bgPanelAlt: semanticPalette.surface3
        readonly property color bgOverlay: '#800A0F1C'
        readonly property color bgStateLayer: AmneziaStyle.mayakDay ? '#14131826' : '#14ECEFF6'
        readonly property color bgStateLayerPressed: AmneziaStyle.mayakDay ? '#1A131826' : '#1AECEFF6'
        readonly property color bgStateLayerAccent: AmneziaStyle.mayakDay ? '#14F2B12E' : '#14FFC54D'
        readonly property color bgSurfaceInverse: AmneziaStyle.mayakDay ? '#18213A' : '#ECEFF6'
        readonly property color bgSurfaceInverseAlt: AmneziaStyle.mayakDay ? '#111827' : '#D4D8E2'
        readonly property color bgControlTrack: semanticPalette.surface2
        readonly property color bgField: semanticPalette.surface1
        readonly property color bgSelected: semanticPalette.surface2
        readonly property color bgAccentSubtle: AmneziaStyle.mayakDay ? '#1AF2B12E' : '#1AFFC54D'
        readonly property color bgStaticWhite: '#FFFFFF'

        readonly property color bgAction: semanticPalette.beam
        readonly property color bgActionHover: AmneziaStyle.mayakDay ? '#E7A21F' : '#FFD36B'
        readonly property color bgActionPress: AmneziaStyle.mayakDay ? '#D69211' : '#E6A92F'

        readonly property color borderFaint: semanticPalette.line
        readonly property color borderSoft: semanticPalette.line
        readonly property color borderMedium: semanticPalette.lineStrong
        readonly property color borderBold: semanticPalette.lineStrong
        readonly property color borderEmphasis: semanticPalette.focus
        readonly property color borderAccent: semanticPalette.beam
        readonly property color borderField: semanticPalette.lineStrong
        readonly property color borderFocus: semanticPalette.focus

        readonly property color accentLight: semanticPalette.beamStrong
        readonly property color accentDefault: semanticPalette.beam
        readonly property color accentDark: AmneziaStyle.mayakDay ? '#8A5B00' : '#E5A92F'
        readonly property color accentDeep: AmneziaStyle.mayakDay ? '#684500' : '#7B5111'

        readonly property color statusDestructive: semanticPalette.danger
        readonly property color statusWarning: semanticPalette.warn
        readonly property color statusSuccess: semanticPalette.ok

        readonly property color promoRecommendation: semanticPalette.focus
        readonly property color promoUpdate: semanticPalette.info
        readonly property color promoOverlay: AmneziaStyle.mayakDay ? '#142B5EA6' : '#148DB4F0'
        readonly property color promoPink: semanticPalette.danger
        readonly property color promoPinkDeep: AmneziaStyle.mayakDay ? '#8A2923' : '#BD5555'

        readonly property color iconDefault: semanticPalette.ink
        readonly property color iconSecondary: semanticPalette.muted
        readonly property color iconTertiary: semanticPalette.lineStrong
        readonly property color iconInverted: semanticPalette.inkOnBeam

        readonly property color shadowLayer1: '#26000000'
        readonly property color shadowLayer2: '#4D000000'
        readonly property color shadowGlow: '#00FBB751'
    }
}
