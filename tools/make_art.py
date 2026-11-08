# SPDX-FileCopyrightText: 2026 SIEMstress contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Generate SIEMstress's icon and logo into src/siemstress/assets/.

    .venv/bin/pip install Hershey-Fonts   # single-stroke fonts, for the logo lettering
    .venv/bin/python tools/make_art.py

Outputs icon.svg, logo.svg, icon-<size>.png, logo.png and logo.txt (Rich-markup braille
art for the terminal UI). The lettering uses a Hershey single-stroke script so each
letter is one pen path, which reads as thread rather than as a filled typeface.
"""

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from HersheyFonts import HersheyFonts
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ASSETS = Path(__file__).resolve().parent.parent / "src" / "siemstress" / "assets"
ICON_SIZES = (16, 22, 24, 32, 48, 64, 128, 256)

THREAD = "#d93f3f"  # the palette's red
THREAD_DARK = "#9e2626"
THREAD_LIGHT = "#f07a7a"
STEEL_OUTLINE = "#4a525e"

DEFS = """
<defs>
  <linearGradient id="steel" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#f4f6f9"/>
    <stop offset="0.45" stop-color="#c3c9d2"/>
    <stop offset="1" stop-color="#7b8492"/>
  </linearGradient>
  <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
    <feDropShadow dx="0" dy="1.5" stdDeviation="1.5" flood-color="#000" flood-opacity="0.25"/>
  </filter>
</defs>"""


def needle(length: float, width: float) -> str:
    """A needle along +x from its tip at (0, 0) to its eye end, eye cut out (even-odd)."""
    half, taper = width / 2, length * 0.32
    eye_x, eye_len, eye_half = length - width * 2.6, width * 2.4, width * 0.17
    body = (
        f"M0,0 C{taper * 0.5},{-half * 0.35} {taper * 0.8},{-half} {taper},{-half}"
        f" L{length - half},{-half} A{half},{half} 0 0 1 {length - half},{half}"
        f" L{taper},{half} C{taper * 0.8},{half} {taper * 0.5},{half * 0.35} 0,0 Z"
    )
    eye = (
        f"M{eye_x},{-eye_half} L{eye_x + eye_len},{-eye_half}"
        f" A{eye_half},{eye_half} 0 0 1 {eye_x + eye_len},{eye_half}"
        f" L{eye_x},{eye_half} A{eye_half},{eye_half} 0 0 1 {eye_x},{-eye_half} Z"
    )
    shine = f"M{taper},{-half * 0.45} L{length - width * 3},{-half * 0.45}"
    return (
        f'<path d="{body} {eye}" fill="url(#steel)" fill-rule="evenodd" '
        f'stroke="{STEEL_OUTLINE}" stroke-width="{width * 0.09:.2f}" stroke-linejoin="round"/>'
        f'<path d="{shine}" stroke="#ffffff" stroke-opacity="0.7" '
        f'stroke-width="{width * 0.12:.2f}" stroke-linecap="round" fill="none"/>'
    )


def thread(d: str, width: float, clip: str | None = None, flat: bool = False) -> str:
    """A strand: dark edge, red body, light core, so it reads as round thread."""
    clip_attr = f' clip-path="url(#{clip})"' if clip else ""
    layers = (
        ((THREAD_DARK, 1.0), (THREAD, 0.72))
        if flat
        else ((THREAD_DARK, 1.0), (THREAD, 0.72), (THREAD_LIGHT, 0.22))
    )
    return (
        f"<g{clip_attr} fill='none' stroke-linecap='round' stroke-linejoin='round'>"
        + "".join(
            f'<path d="{d}" stroke="{color}" stroke-width="{width * scale:.2f}"/>'
            for color, scale in layers
        )
        + "</g>"
    )


def icon_svg(bold: bool = False) -> str:
    """Needle on the diagonal, tip bottom-left, eye top-right; the thread leaves the eye
    and draws a cursive S that crosses the needle in the middle.

    `bold` thickens everything and drops the shading, for 16-24px tray sizes.
    """
    strand, steel = (24, 30) if bold else (15, 22)
    shadow = "" if bold else ' filter="url(#shadow)"'
    s_curve = (
        "M206,50 C178,28 116,24 94,54 C72,84 88,114 128,128"
        " C168,142 196,172 172,202 C150,230 88,226 64,200 C54,188 58,172 74,170"
    )
    tail = "M206,50 C216,40 226,30 240,32"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" \
width="256" height="256">
{DEFS}
<defs>
  <clipPath id="front-middle"><circle cx="128" cy="128" r="24"/></clipPath>
  <clipPath id="front-tail"><circle cx="232" cy="30" r="24"/></clipPath>
</defs>
<g{shadow}>
  <g id="thread-back">{thread(s_curve + " " + tail, strand, flat=bold)}</g>
  <g id="needle" transform="translate(40,216) rotate(-45)">{needle(250, steel)}</g>
  <g id="thread-front">{thread(s_curve, strand, "front-middle", bold)}\
{thread(tail, strand, "front-tail", bold)}</g>
</g>
</svg>"""


def smooth(points: list[tuple[float, float]]) -> str:
    """Catmull-Rom spline through the points, as SVG path data."""
    if len(points) < 3:
        return "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in points)
    p = [points[0], *points, points[-1]]
    d = f"M{p[1][0]:.1f},{p[1][1]:.1f}"
    for i in range(1, len(p) - 2):
        (x0, y0), (x1, y1), (x2, y2), (x3, y3) = p[i - 1], p[i], p[i + 1], p[i + 2]
        d += (
            f" C{x1 + (x2 - x0) / 6:.1f},{y1 + (y2 - y0) / 6:.1f}"
            f" {x2 - (x3 - x1) / 6:.1f},{y2 - (y3 - y1) / 6:.1f} {x2:.1f},{y2:.1f}"
        )
    return d


def lettering(text: str, x: float, baseline: float, height: float) -> list[list[tuple]]:
    font = HersheyFonts()
    font.load_default_font("cursive")
    font.normalize_rendering(height)
    return [
        [(x + px, baseline - py) for px, py in stroke] for stroke in font.strokes_for_text(text)
    ]


def logo_svg() -> str:
    """A level needle whose thread runs out of the eye and writes the name."""
    width, height, needle_y, needle_len, steel = 1000, 216, 132, 300, 24
    eye_x = 30 + needle_len - steel * 2.6 + steel * 1.2
    strokes = lettering("Siemstress", 356, 172, 150)
    first_x, first_y = strokes[0][0]
    # Out of the eye, a little slack, then up into the S's entry stroke.
    lead = (
        f"M{eye_x:.1f},{needle_y} C{eye_x + 30:.1f},{needle_y + 34}"
        f" {first_x - 34:.1f},{first_y + 22:.1f} {first_x:.1f},{first_y:.1f}"
    )
    # The loose end, hanging behind the needle on the other side of the eye.
    tail = (
        f"M{eye_x:.1f},{needle_y} C{eye_x - 16:.1f},{needle_y + 26}"
        f" {eye_x - 60:.1f},{needle_y + 44} {eye_x - 96:.1f},{needle_y + 36}"
    )
    words = " ".join(smooth(stroke) for stroke in strokes)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" \
width="{width}" height="{height}">
{DEFS}
<g filter="url(#shadow)">
  <g id="thread-back">{thread(tail, 9)}</g>
  <g id="needle" transform="translate(30,{needle_y})">{needle(needle_len, steel)}</g>
  <g id="thread-front">{thread(lead + " " + words, 9)}</g>
</g>
</svg>"""


def render(svg: str, width: int, height: int, element: str | None = None) -> QImage:
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    image = QImage(width, height, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    if element:
        renderer.render(painter, element, _element_rect(renderer, element, width, height))
    else:
        renderer.render(painter)
    painter.end()
    return image


def _element_rect(renderer: QSvgRenderer, element: str, width: int, height: int) -> QRectF:
    # Render a single layer where it sits in the full picture.
    box = renderer.transformForElement(element).mapRect(renderer.boundsOnElement(element))
    view = renderer.viewBoxF()
    sx, sy = width / view.width(), height / view.height()
    return QRectF(box.x() * sx, box.y() * sy, box.width() * sx, box.height() * sy)


def braille(svg: str, columns: int, rows: int) -> str:
    """Rich-markup braille art: each cell is 2x4 dots, colored by the layer it shows."""
    w, h = columns * 2, rows * 4
    layers = {
        STEEL_OUTLINE: render(svg, w, h, "needle"),
        THREAD: render(svg, w, h, "thread-back"),
    }
    front = render(svg, w, h, "thread-front")
    dots = ((0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04), (1, 0, 0x08),
            (1, 1, 0x10), (1, 2, 0x20), (0, 3, 0x40), (1, 3, 0x80))  # fmt: skip
    lines = []
    for row in range(rows):
        line = []
        for col in range(columns):
            bits, weight = 0, {color: 0 for color in layers}
            for dx, dy, bit in dots:
                x, y = col * 2 + dx, row * 4 + dy
                alphas = {c: img.pixelColor(x, y).alpha() for c, img in layers.items()}
                alphas[THREAD] = max(alphas[THREAD], front.pixelColor(x, y).alpha())
                if max(alphas.values()) > 90:
                    bits |= bit
                    for color, alpha in alphas.items():
                        weight[color] += alpha
            if bits:
                color = "#9aa3af" if max(weight, key=weight.get) == STEEL_OUTLINE else THREAD
                line.append(f"[{color}]{chr(0x2800 + bits)}[/]")
            else:
                line.append(" ")
        lines.append("".join(line).rstrip())
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def main() -> None:
    app = QGuiApplication([])  # noqa: F841 - Qt needs an application to render
    ASSETS.mkdir(parents=True, exist_ok=True)
    icon, logo = icon_svg(), logo_svg()
    (ASSETS / "icon.svg").write_text(icon)
    (ASSETS / "logo.svg").write_text(logo)
    bold = icon_svg(bold=True)
    for size in ICON_SIZES:
        render(bold if size <= 24 else icon, size, size).save(str(ASSETS / f"icon-{size}.png"))
    render(logo, 1000, 216).save(str(ASSETS / "logo.png"))
    (ASSETS / "logo.txt").write_text(braille(logo, 96, 14))
    print(f"wrote {len(list(ASSETS.iterdir()))} files to {ASSETS}")


if __name__ == "__main__":
    main()
