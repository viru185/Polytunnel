"""Regenerate the app icon: assets/polytunnel.ico, assets/polytunnel.png and assets/polytunnel-512.png.

Original artwork drawn with plain shapes (no fonts, no third-party art): "Arch and light", a
tunnel arch with flat feet and a white light inside, on an indigo rounded square.

Sizes 16, 20, 24 and 32 are drawn on whole pixels (their own geometry) so they stay crisp; 40 px
and up are scaled from the 1024 px master. Below 48 px there is no halo and no sheen.

    uv run --no-project --with pillow python assets/make_icon.py
"""

from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageOps

HERE = Path(__file__).resolve().parent
TOP, BOTTOM = (0x7C, 0x8B, 0xFF), (0x3A, 0x2B, 0xC0)
HALO = (0xC7, 0xCE, 0xFF)
WHITE = (255, 255, 255, 255)
SS = 16  # supersampling for the hand-fitted small sizes


def diagonal_gradient(size: int) -> Image.Image:
    """TOP at the top-left corner to BOTTOM at the bottom-right corner."""
    v = Image.linear_gradient("L").resize((size, size))
    h = v.rotate(90, expand=False)
    diag = ImageChops.add(v, h, scale=2.0)
    return ImageOps.colorize(diag, black=TOP, white=BOTTOM).convert("RGBA")


def rounded_mask(size: int, box, radius: float) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(box, radius=radius, fill=255)
    return mask


def arch(draw: ImageDraw.ImageDraw, cx, top_cy, radius, stroke, foot, fill=WHITE):
    """A tunnel arch: a half ring (centre line `radius`, width `stroke`) on two straight legs
    down to `foot`, with flat ends."""
    outer = radius + stroke / 2
    draw.arc(
        [cx - outer, top_cy - outer, cx + outer, top_cy + outer],
        start=180,
        end=360,
        fill=fill,
        width=round(stroke),
    )
    for x in (cx - radius, cx + radius):
        draw.rectangle([x - stroke / 2, top_cy, x + stroke / 2, foot], fill=fill)


def master(halo: bool, sheen: bool) -> Image.Image:
    s = 1024
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    box, radius = [40, 40, s - 40, s - 40], 224
    img.paste(diagonal_gradient(s), (0, 0), rounded_mask(s, box, radius))
    if sheen:
        shine = Image.new("RGBA", (s, s), (255, 255, 255, 0))
        alpha = Image.linear_gradient("L").resize((s, s)).point(lambda v: max(0, 41 - v * 82 // 255))
        shine.putalpha(ImageChops.multiply(alpha, rounded_mask(s, box, radius)))
        img = Image.alpha_composite(img, shine)
        rim = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        ImageDraw.Draw(rim).rounded_rectangle(
            [41, 41, s - 41, s - 41], radius=radius - 1, outline=(255, 255, 255, 36), width=3
        )
        img = Image.alpha_composite(img, rim)
    if halo:
        # Alpha 0.5 at the centre, fading linearly to 0 at radius 150.
        glow = Image.new("L", (300, 300), 0)
        glow.putdata(
            [
                round(128 * max(0.0, 1 - ((x - 149.5) ** 2 + (y - 149.5) ** 2) ** 0.5 / 150))
                for y in range(300)
                for x in range(300)
            ]
        )
        layer = Image.new("RGBA", (s, s), HALO + (0,))
        a = Image.new("L", (s, s), 0)
        a.paste(glow, (512 - 150, 640 - 150))
        layer.putalpha(a)
        img = Image.alpha_composite(img, layer)
    d = ImageDraw.Draw(img)
    arch(d, 512, 488, 190, 124, 788)
    d.ellipse([512 - 60, 640 - 60, 512 + 60, 640 + 60], fill=WHITE)
    return img


def small(size: int) -> Image.Image:
    """Hand-fitted geometry in target pixels, drawn SS× larger and box-filtered down."""
    spec = {
        # background box (x0, y0, x1, y1), radius; arch cx, top centre y, radius, stroke, foot;
        # light: ("rect", x0, y0, x1, y1) or ("dot", cx, cy, r)
        16: ((0, 0, 16, 16), 4, (8, 8, 4, 2, 13), ("rect", 7, 9, 9, 11)),
        20: ((1, 1, 19, 19), 4.5, (10, 10, 4, 2, 16), ("rect", 9, 11, 11, 13)),
        24: ((1, 1, 23, 23), 5.5, (12, 12, 5.5, 3, 20), ("rect", 11, 14, 13, 16)),
        32: ((1, 1, 31, 31), 7.5, (16, 15, 6, 4, 25), ("dot", 16, 20, 2.25)),
    }[size]
    (box, radius, (cx, cy, r, stroke, foot), light) = spec
    k = SS
    big = size * k
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    scaled = [v * k for v in box]
    img.paste(diagonal_gradient(big), (0, 0), rounded_mask(big, scaled, radius * k))
    d = ImageDraw.Draw(img)
    arch(d, cx * k, cy * k, r * k, stroke * k, foot * k)
    if light[0] == "rect":
        d.rectangle([v * k for v in light[1:]], fill=WHITE)
    else:
        _, lx, ly, lr = light
        d.ellipse([(lx - lr) * k, (ly - lr) * k, (lx + lr) * k, (ly + lr) * k], fill=WHITE)
    return img.resize((size, size), Image.Resampling.BOX)


def icon(size: int) -> Image.Image:
    if size in (16, 20, 24, 32):
        return small(size)
    return master(halo=size >= 48, sheen=size >= 48).resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    images = [icon(s) for s in sizes]
    images[-1].save(HERE / "polytunnel.png", optimize=True)
    icon(512).save(HERE / "polytunnel-512.png", optimize=True)
    images[-1].save(HERE / "polytunnel.ico", sizes=[(s, s) for s in sizes], append_images=images[:-1])
    print("wrote", HERE / "polytunnel.ico", HERE / "polytunnel.png", HERE / "polytunnel-512.png")


if __name__ == "__main__":
    main()
