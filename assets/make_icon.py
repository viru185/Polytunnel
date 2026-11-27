"""Regenerate the app icon (assets/polytunnel.ico and assets/polytunnel.png).

Original artwork drawn with plain shapes (no fonts, no third-party art): three nested tunnel
arches on a teal-to-indigo rounded square.

    uv run --no-project --with pillow python assets/make_icon.py
"""

from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
S = 1024  # master canvas size; every output size is downsampled from it


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def master() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # Background: rounded square with a diagonal teal -> indigo gradient.
    grad = Image.new("RGBA", (S, S))
    top, bottom = (20, 184, 166), (67, 56, 202)
    draw = ImageDraw.Draw(grad)
    for y in range(S):
        draw.line([(0, y), (S, y)], fill=lerp(top, bottom, y / (S - 1)) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=220, fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    floor = 800
    # Three nested arches (outer to inner), each a thick white ring cut at the floor.
    for i, (half, thick) in enumerate([(330, 70), (230, 62), (135, 54)]):
        cx = S // 2
        box = [cx - half, floor - 2 * half + 120, cx + half, floor + 120]
        alpha = 255 - i * 45
        d.arc(box, start=180, end=360, fill=(255, 255, 255, alpha), width=thick)
        # Straight legs down to the floor.
        d.rectangle([box[0], (box[1] + box[3]) // 2, box[0] + thick, floor], fill=(255, 255, 255, alpha))
        d.rectangle([box[2] - thick, (box[1] + box[3]) // 2, box[2], floor], fill=(255, 255, 255, alpha))
    # The road into the tunnel.
    d.rounded_rectangle([200, floor, S - 200, floor + 54], radius=27, fill=white)
    return img


def main() -> None:
    big = master()
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    big.resize((256, 256), Image.LANCZOS).save(HERE / "polytunnel.png", optimize=True)
    big.resize((256, 256), Image.LANCZOS).save(
        HERE / "polytunnel.ico", sizes=[(s, s) for s in sizes]
    )
    print("wrote", HERE / "polytunnel.ico", HERE / "polytunnel.png")


if __name__ == "__main__":
    main()
