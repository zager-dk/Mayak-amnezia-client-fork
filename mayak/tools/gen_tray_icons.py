"""Generate Mayak Windows tray icons: the main-screen (F7) lighthouse as a silhouette, no beams.

The silhouette follows MayakBeacon F7 (client/ui/qml/newComponents/Mayak/assets): antenna with a
ball, half-ellipse dome, lamp room, gallery and a tapered tower. F7 is about 1:4 wide; at 16 px
that is a 4 px sliver, so the tray glyph widens the proportions on a 32-unit grid while keeping
those parts. The lamp carries the state:
  off         dark lamp (window cut-out)       connecting  dim gold lamp
  on          gold lamp                         error       dark lamp + red badge
Themes: 'dark' = dark taskbar (white silhouette), 'light' = light taskbar (dark silhouette).
gen_android_icons.py imports `silhouette()` so the notification/themed icons are the same shape.
Usage: python -I gen_tray_icons.py <output-dir>
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw

SIZES = (16, 20, 24, 32, 40, 48)
SS = 16  # supersampling factor
THEMES = {
    'dark': {'body': (255, 255, 255, 255), 'gold': (255, 200, 92, 255)},
    'light': {'body': (26, 31, 43, 255), 'gold': (194, 124, 0, 255)},
}
RED = (229, 72, 77, 255)
CLEAR = (0, 0, 0, 0)


def silhouette(lamp_state):
    """Shapes on the 32-unit grid as (kind, geometry, role); role is body | lamp | cut.
    lamp_state: 'lit' (lamp room filled with the lamp colour) or 'dark' (body + window cut-out)."""
    s = [
        ('ellipse', (14.7, 0.2, 17.3, 2.8), 'body'),           # antenna ball
        ('rect', (15.4, 2.0, 16.6, 4.6), 'body'),              # antenna mast
        ('dome', (10.5, 3.6, 21.5, 12.4), 'body'),             # upper half of this ellipse box
        ('rect', (12.0, 8.0, 20.0, 14.5), 'lamp' if lamp_state == 'lit' else 'body'),
        ('rect', (9.5, 14.5, 22.5, 16.8), 'body'),             # gallery
        ('poly', [(11.4, 16.8), (20.6, 16.8), (23.2, 31.0), (8.8, 31.0)], 'body'),  # tower
    ]
    if lamp_state == 'dark':
        s.append(('rect', (13.6, 9.6, 18.4, 12.9), 'cut'))    # lamp window
    return s


def paint(d, shapes, P, colours):
    for kind, g, role in shapes:
        fill = colours[role]
        if kind == 'poly':
            d.polygon([P(x, y) for x, y in g], fill=fill)
            continue
        x0, y0 = P(g[0], g[1]); x1, y1 = P(g[2], g[3])
        if kind == 'rect':
            d.rectangle([x0, y0, x1 - 1, y1 - 1], fill=fill)
        elif kind == 'ellipse':
            d.ellipse([x0, y0, x1, y1], fill=fill)
        elif kind == 'dome':
            d.pieslice([x0, y0, x1, y1], 180, 360, fill=fill)


def draw(state, theme, size):
    t = THEMES[theme]
    big = size * SS
    k = big / 32.0
    img = Image.new('RGBA', (big, big), CLEAR)
    d = ImageDraw.Draw(img)
    body, gold = t['body'], t['gold']
    lamp = gold if state == 'on' else (gold[0], gold[1], gold[2], int(gold[3] * 0.6))
    shapes = silhouette('lit' if state in ('on', 'connecting') else 'dark')
    paint(d, shapes, lambda x, y: (x * k, y * k), {'body': body, 'lamp': lamp, 'cut': CLEAR})
    if state == 'error':
        # Transparent ring separates the badge from the tower, then the red dot.
        d.ellipse([19 * k, 17 * k, 32 * k, 30 * k], fill=CLEAR)
        d.ellipse([20.5 * k, 18.5 * k, 30.5 * k, 28.5 * k], fill=RED)
    return img.resize((size, size), Image.LANCZOS)


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    names = []
    for state in ('off', 'connecting', 'on', 'error'):
        for theme in THEMES:
            for size in SIZES:
                name = f'{state}-{theme}-{size}.png'
                draw(state, theme, size).save(out / name, optimize=True)
                names.append(name)
    print(f'{len(names)} icons -> {out}')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'tray-out')
