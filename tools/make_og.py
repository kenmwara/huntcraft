#!/usr/bin/env python3
"""Draw the brand images from one mark, in Inter (the site's font, bundled in tools/fonts, SIL OFL):
site/og.png (1200x630: mark, name, one line, no stats), site/favicon.svg and site/favicon.ico.
Run once after a brand change: python tools/make_og.py"""
import pathlib
from PIL import Image, ImageDraw, ImageFont

HERE = pathlib.Path(__file__).resolve().parent
SITE = HERE.parent / "site"
W, H = 1200, 630
BG, INK, MUTED, ACCENT = "#0b1020", "#e5e9f0", "#a3adbf", "#6b9bff"   # the site's dark tokens
LIGHT_ACCENT = "#2563eb"                                              # the site's light accent (favicon)


def inter(size, weight):
    f = ImageFont.truetype(str(HERE / "fonts" / "Inter.ttf"), size)
    f.set_variation_by_axes([min(max(size, 14), 32), weight])       # axes: optical size, weight
    return f


def mark(d, ox, oy, s, color):
    """The magnifier in a 32-unit box: circle r=8 at (14,14), handle to (28.5,28.5)."""
    d.ellipse([ox + 6 * s, oy + 6 * s, ox + 22 * s, oy + 22 * s], outline=color, width=max(1, round(3 * s)))
    d.line([ox + 20 * s, oy + 20 * s, ox + 28.5 * s, oy + 28.5 * s], fill=color, width=max(1, round(3 * s)))


img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)
mark(d, 96, 175, 7.0, ACCENT)
d.text((340, 200), "HuntCraft", font=inter(118, 800), fill=INK)
d.text((346, 350), "Follow the reasoning. Run the queries yourself.", font=inter(34, 400), fill=MUTED)
d.text((346, 396), "Find the flag on your own.", font=inter(34, 400), fill=MUTED)
d.rectangle([0, H - 10, W, H], fill=ACCENT)
img.save(SITE / "og.png", optimize=True)

# favicon: a solid accent tile with a white mark, so it reads on light and dark browser tabs alike
(SITE / "favicon.svg").write_text(
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="{LIGHT_ACCENT}"/>'
    '<g transform="translate(3.5 3.5) scale(.78)" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round">'
    '<circle cx="14" cy="14" r="8"/><line x1="20" y1="20" x2="27" y2="27"/></g></svg>\n', encoding="utf-8")


def tile(px, rounded):
    big = px * 4                                                         # drawn 4x, downsampled for smooth edges
    im = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    if rounded:
        d.rounded_rectangle([0, 0, big - 1, big - 1], radius=big * 7 // 32, fill=LIGHT_ACCENT)
    else:
        d.rectangle([0, 0, big, big], fill=LIGHT_ACCENT)                 # iOS rounds it; transparent corners go black
    s = big / 32 * .78
    o = big / 32 * 3.5
    d.ellipse([o + 6 * s, o + 6 * s, o + 22 * s, o + 22 * s], outline="white", width=round(4 * s))
    d.line([o + 20 * s, o + 20 * s, o + 27 * s, o + 27 * s], fill="white", width=round(4 * s))
    r = round(2 * s)
    d.ellipse([o + 27 * s - r, o + 27 * s - r, o + 27 * s + r, o + 27 * s + r], fill="white")  # round line cap
    return im.resize((px, px), Image.LANCZOS)


tile(256, True).save(SITE / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
tile(180, False).convert("RGB").save(SITE / "apple-touch-icon.png", optimize=True)
print("wrote og.png, favicon.svg, favicon.ico, apple-touch-icon.png in", SITE)
