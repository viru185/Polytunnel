"""Regenerate the installer wizard's placeholder art (packaging/windows/dialog.bmp and
banner.bmp) with the app icon, assets/polytunnel.png.

    uv run --no-project --with pillow python packaging/windows/make_art.py [--scale N]

dialog.bmp fills the Welcome and Finish style pages above the buttons (370 x 234 installer
units, 493 x 312 pixels at 100% display scaling): an indigo glow on near-black, the logo at
the top left, and a bottom band that fades to the window colour (#F0F0F0) for the Finish
page's check boxes, which are opaque and fill behind their labels with that colour.
banner.bmp is the strip at the top of the other pages (370 x 44 units, 493 x 58 pixels): a
plain indigo gradient with the logo on the right. The wizard draws all the words. Windows
Installer stretches a bitmap to its control, so --scale 2 (the default) draws them at twice
that size to stay sharp on 150-200% displays.
"""

import argparse
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
ICON = HERE.parent.parent / "assets" / "polytunnel.png"

# The glow: centre, middle and edge colours.
GLOW = [(0.0, (0x2B, 0x2F, 0x8F)), (0.55, (0x0B, 0x0C, 0x22)), (1.0, (0x05, 0x06, 0x08))]
EDGE = GLOW[-1][1]
FACE = (0xF0, 0xF0, 0xF0)  # Windows' dialog (button face) colour, behind check box labels
BANNER = ((0x0B, 0x0C, 0x22), (0x1B, 0x1F, 0x5E))  # left, right


def mix(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def ramp(stops, t):
    """The colour at `t` (0..1) along `stops` [(position, colour), ...]."""
    for (p0, c0), (p1, c1) in zip(stops, stops[1:]):
        if t <= p1:
            return mix(c0, c1, (t - p0) / (p1 - p0))
    return stops[-1][1]


def glow(size, center, radii):
    """`size` filled with EDGE and an elliptical GLOW centred on `center`."""
    img = Image.new("RGB", size, EDGE)
    # Pillow's radial gradient: 0 in the middle, 255 at the inscribed circle and beyond.
    dist = Image.radial_gradient("L").resize((2 * radii[0], 2 * radii[1]), Image.BICUBIC)
    channels = [dist.point([ramp(GLOW, i / 255)[c] for i in range(256)]) for c in range(3)]
    img.paste(Image.merge("RGB", channels), (center[0] - radii[0], center[1] - radii[1]))
    return img


def logo(img, scale, left_top, size):
    """Puts the icon, `size` 100%-scaling pixels square, at `left_top`, resized once from
    the 256-pixel master."""
    px = size * scale
    mark = Image.open(ICON).convert("RGBA").resize((px, px), Image.LANCZOS)
    out = img.convert("RGBA")
    out.alpha_composite(mark, (left_top[0] * scale, left_top[1] * scale))
    return out.convert("RGB")


def dialog(scale):
    """493 x 312 (x scale). Logo at x, y = 27, 24 (48 x 48), text from y = 83, and from
    y = 192 a fade to FACE that is solid from y = 240 down."""
    w, h = 493 * scale, 312 * scale
    img = glow((w, h), (150 * scale, 70 * scale), (380 * scale, 260 * scale))
    top, solid = 192 * scale, 240 * scale
    mask = Image.new("L", (1, h), 0)
    for y in range(top, h):
        t = min(1.0, (y - top) / (solid - top))
        mask.putpixel((0, y), round(255 * t * t * (3 - 2 * t)))  # smoothstep
    img.paste(Image.new("RGB", (w, h), FACE), (0, 0), mask.resize((w, h)))
    return logo(img, scale, (27, 24), 48)


def banner(scale):
    """493 x 58 (x scale): a left-to-right indigo gradient, title on the left, logo (32 x 32)
    on the right."""
    w, h = 493 * scale, 58 * scale
    row = Image.new("RGB", (w, 1))
    for x in range(w):
        row.putpixel((x, 0), mix(*BANNER, x / (w - 1)))
    return logo(row.resize((w, h)), scale, (445, 13), 32)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scale", type=int, default=2, help="pixels per 100%%-scaling pixel")
    parser.add_argument("--out", type=Path, default=HERE, help="output folder")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, art in (("dialog.bmp", dialog), ("banner.bmp", banner)):
        art(args.scale).save(args.out / name)
        print("wrote", args.out / name)


if __name__ == "__main__":
    main()
