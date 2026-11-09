"""Generate Mayak Android launcher, monochrome and notification icons.

Launcher (adaptive): the main-screen MayakBeacon F7 lighthouse (assets/mayak-f7-small-on.svg)
adapted to an icon: blue sky background, dark land, dark striped tower with gold rim light,
gold lamp with glow and a soft fading beam to the right (no hard-edged triangle). Tower and lamp
sit inside the 66 dp safe circle; land and beam bleed to the edges so every mask looks complete.
Monochrome (themed, Android 13+) and the notification/quick-settings vector use the beamless
tray silhouette from gen_tray_icons.py, so every small surface shows the same shape.

  mipmap-*/ic_launcher_foreground.png  108 dp foreground layer
  drawable/ic_launcher_background.xml  sky gradient (vector-free shape)
  mipmap-*/ic_launcher_monochrome.png  108 dp themed layer (alpha only)
  mipmap-*/icon.png, icon_round.png    48 dp pre-adaptive fallback
  drawable/ic_amnezia_round.xml        white silhouette, 24 dp (name kept: fork code untouched)
Usage: python -I gen_android_icons.py <client/android/res>
"""
import math
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I drops the script dir
from gen_tray_icons import silhouette, paint  # noqa: E402

SS = 4
DENSITY = {'ldpi': 0.75, 'mdpi': 1.0, 'hdpi': 1.5, 'xhdpi': 2.0, 'xxhdpi': 3.0, 'xxxhdpi': 4.0}
SKY_TOP, SKY_BOTTOM = '#12234D', '#4569B8'
TOWER, STRIPE, LAND = (7, 10, 19, 255), (26, 36, 64, 255), (5, 7, 13, 255)
LAMP, RIM = (255, 210, 122, 255), (255, 197, 77, 255)
WHITE, CLEAR = (255, 255, 255, 255), (0, 0, 0, 0)

# F7 scene units -> dp on the 108 dp canvas: tower centre x=118 at 45 dp, antenna top y=46 at 23 dp.
S = 0.48
def F(x, y):
    return 45 + (x - 118) * S, 23 + (y - 46) * S


def hexrgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def sky(px):
    top, bottom = hexrgb(SKY_TOP), hexrgb(SKY_BOTTOM)
    img = Image.new('RGBA', (px, px))
    d = ImageDraw.Draw(img)
    for y in range(px):
        t = min(1.0, y / (px * 0.75))
        d.line([(0, y), (px, y)], fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    return img


def quad(p0, p1, p2, n=24):
    return [((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
             (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]) for t in (i / n for i in range(n + 1))]


def foreground(density):
    px = round(108 * density)
    big = px * SS
    k = density * SS
    P = lambda x, y: tuple(v * k for v in F(x, y))
    D = lambda x, y: (x * k, y * k)  # dp coordinates
    img = Image.new('RGBA', (big, big), CLEAR)

    # Soft beam: horizontal alpha gradient inside a wedge from the lamp, fading out before the edge.
    lx, ly = F(118, 73)
    end = 112.0
    wedge = Image.new('L', (big, big), 0)
    ImageDraw.Draw(wedge).polygon([D(lx, ly - 1.2), D(end, ly - (end - lx) * 0.33), D(end, ly + (end - lx) * 0.33), D(lx, ly + 1.2)], fill=255)
    core = Image.new('L', (big, big), 0)
    ImageDraw.Draw(core).polygon([D(lx, ly - 0.8), D(end, ly - (end - lx) * 0.12), D(end, ly + (end - lx) * 0.12), D(lx, ly + 0.8)], fill=255)
    ramp = Image.new('L', (big, 1))
    for x in range(big):
        t = max(0.0, (x / k - lx) / (end - lx))
        ramp.putpixel((x, 0), round(255 * max(0.0, 1 - t) ** 1.4))
    ramp = ramp.resize((big, big))
    for mask, colour, strength in ((wedge, RIM, 0.62), (core, (255, 240, 200, 255), 0.85)):
        a = Image.new('L', (big, big), 0)
        a.paste(ramp, (0, 0), mask)
        a = a.point(lambda v: round(v * strength)).filter(ImageFilter.GaussianBlur(1.2 * k))
        layer = Image.new('RGBA', (big, big), colour)
        layer.putalpha(a)
        img.alpha_composite(layer)

    # Lamp glow.
    glow = Image.new('L', (big, big), 0)
    r = 13 * S * k
    cx, cy = D(lx, ly)
    ImageDraw.Draw(glow).ellipse([cx - r, cy - r, cx + r, cy + r], fill=150)
    glow = glow.filter(ImageFilter.GaussianBlur(5 * S * k))
    g = Image.new('RGBA', (big, big), LAMP)
    g.putalpha(glow)
    img.alpha_composite(g)

    d = ImageDraw.Draw(img)
    # Land: F7 ridge, extended to the canvas edges and bottom (full bleed).
    ridge = [P(0, 162)] + quad(P(0, 162), P(30, 150), P(60, 156)) + [P(150, 154)] + quad(P(150, 154), P(174, 164), P(190, 178))
    d.polygon([D(-2, F(0, 162)[1])] + ridge + [D(110, F(190, 178)[1]), D(110, 110), D(-2, 110)], fill=LAND)

    # Tower with stripes, gallery, dome, antenna (F7 symbol f7-tower).
    tower = [P(104, 156), P(110.5, 88), P(125.5, 88), P(132, 156)]
    d.polygon(tower, fill=TOWER)
    stripes = Image.new('RGBA', (big, big), CLEAR)
    sd = ImageDraw.Draw(stripes)
    for y0 in (104, 127):
        sd.rectangle([*P(96, y0), *P(140, y0 + 9)], fill=STRIPE)
    tmask = Image.new('L', (big, big), 0)
    ImageDraw.Draw(tmask).polygon(tower, fill=255)
    img.paste(stripes, (0, 0), Image.composite(stripes.getchannel('A'), Image.new('L', (big, big), 0), tmask))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([*P(103, 83), *P(133, 88)], radius=1.5 * S * k, fill=TOWER)
    d.pieslice([*P(106, 54), *P(130, 74)], 180, 360, fill=TOWER)
    d.rectangle([*P(117, 48), *P(119, 57)], fill=TOWER)
    bx, by = P(118, 48)
    d.ellipse([bx - 2 * S * k, by - 2 * S * k, bx + 2 * S * k, by + 2 * S * k], fill=TOWER)
    d.rounded_rectangle([*P(109, 64), *P(127, 83)], radius=2 * S * k, fill=LAMP)

    # Gold rim light (right side), round caps.
    w = max(1, round(2.4 * S * k))
    def stroke(points):
        d.line(points, fill=RIM, width=w, joint='curve')
        for p in (points[0], points[-1]):
            d.ellipse([p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2], fill=RIM)
    stroke([P(125.5, 88), P(132, 156)])
    stroke([P(133, 83.5), P(126, 83.5)])
    stroke([P(118 + 12 * math.cos(a), 64 - 10 * math.sin(a)) for a in (math.radians(v) for v in range(0, 76, 5))])
    return img.resize((px, px), Image.LANCZOS)


def silhouette_layer(px, height_px, centre):
    big = px * SS
    k = height_px * SS / 31.0
    ox, oy = centre[0] * SS - 16 * k, centre[1] * SS - 15.6 * k
    img = Image.new('RGBA', (big, big), CLEAR)
    paint(ImageDraw.Draw(img), silhouette('dark'), lambda x, y: (ox + x * k, oy + y * k),
          {'body': WHITE, 'lamp': WHITE, 'cut': CLEAR})
    return img.resize((px, px), Image.LANCZOS)


def legacy(density, round_shape):
    px = round(48 * density)
    scale = px / (72 * density)                       # 48 dp tile shows the central 72 of 108 dp
    full = round(108 * density * scale)
    tile = sky(full)
    tile.alpha_composite(foreground(density).resize((full, full), Image.LANCZOS))
    c = (full - px) // 2
    tile = tile.crop((c, c, c + px, c + px))
    mask = Image.new('L', (px * SS, px * SS), 0)
    md = ImageDraw.Draw(mask)
    if round_shape:
        md.ellipse([0, 0, px * SS - 1, px * SS - 1], fill=255)
    else:
        md.rounded_rectangle([0, 0, px * SS - 1, px * SS - 1], radius=px * SS * 0.22, fill=255)
    out = Image.new('RGBA', (px, px), CLEAR)
    out.paste(tile, (0, 0), mask.resize((px, px), Image.LANCZOS))
    return out


def notification_vector(lit=False):
    """lit=True: connected (solid lamp room); False: not connected (lamp window as a hole)."""
    paths = []
    for kind, g, role in silhouette('lit' if lit else 'dark'):
        if role == 'cut':
            continue
        if kind == 'poly':
            p = 'M' + 'L'.join(f'{x:g},{y:g}' for x, y in g) + 'Z'
        elif kind == 'rect':
            x0, y0, x1, y1 = g
            p = f'M{x0:g},{y0:g}L{x1:g},{y0:g}L{x1:g},{y1:g}L{x0:g},{y1:g}Z'
            if not lit and (x0, y0) == (12.0, 8.0):   # dark lamp room: the window as a hole
                p += 'M13.6,9.6L13.6,12.9L18.4,12.9L18.4,9.6Z'
        elif kind == 'ellipse':
            x0, y0, x1, y1 = g
            rx, ry, cy = (x1 - x0) / 2, (y1 - y0) / 2, (y0 + y1) / 2
            p = f'M{x0:g},{cy:g}A{rx:g},{ry:g} 0 1,0 {x1:g},{cy:g}A{rx:g},{ry:g} 0 1,0 {x0:g},{cy:g}Z'
        else:  # dome: upper half of the ellipse box
            x0, y0, x1, y1 = g
            rx, ry, cy = (x1 - x0) / 2, (y1 - y0) / 2, (y0 + y1) / 2
            p = f'M{x0:g},{cy:g}A{rx:g},{ry:g} 0 0,1 {x1:g},{cy:g}Z'
        # Not connected: dimmed (status-bar icons keep alpha), so lit/unlit reads even at 24 dp.
        alpha = '' if lit else ' android:fillAlpha="0.5"'
        paths.append(f'  <path android:fillColor="#FFFFFF"{alpha} android:fillType="evenOdd" android:pathData="{p}"/>')
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            + ('<!-- Маяк: белый силуэт, фонарь горит — подключено (уведомление, плитка).\n' if lit else
               '<!-- Маяк: белый силуэт, окно фонаря пустое — не подключено (уведомление, плитка).\n') +
            '     Сгенерировано mayak/tools/gen_android_icons.py из силуэта значка в трее. -->\n'
            '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
            '    android:width="24dp"\n    android:height="24dp"\n'
            '    android:viewportWidth="32"\n    android:viewportHeight="32">\n'
            + '\n'.join(paths) + '\n</vector>\n')


def background_xml():
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<!-- Маяк: небо адаптивной иконки (как на главном экране). gen_android_icons.py -->\n'
            '<shape xmlns:android="http://schemas.android.com/apk/res/android" android:shape="rectangle">\n'
            f'    <gradient android:angle="270" android:startColor="{SKY_TOP}" android:endColor="{SKY_BOTTOM}" />\n'
            '</shape>\n')


def main(res):
    res = Path(res)
    written = []
    for name, density in DENSITY.items():
        folder = res / f'mipmap-{name}'
        folder.mkdir(parents=True, exist_ok=True)
        px = round(108 * density)
        for fname, img in (('ic_launcher_foreground.png', foreground(density)),
                           ('ic_launcher_monochrome.png', silhouette_layer(px, 44 * density, (54 * density, 54 * density))),
                           ('icon.png', legacy(density, False)),
                           ('icon_round.png', legacy(density, True))):
            img.save(folder / fname, optimize=True)
            written.append(folder / fname)
    for rel, text in (('drawable/ic_amnezia_round.xml', notification_vector(lit=False)),
                      ('drawable/ic_mayak_status_on.xml', notification_vector(lit=True)),
                      ('drawable/ic_launcher_background.xml', background_xml())):
        (res / rel).write_text(text, encoding='utf-8', newline='\n')
        written.append(res / rel)
    print(f'{len(written)} files -> {res}')


if __name__ == '__main__':
    main(sys.argv[1])
