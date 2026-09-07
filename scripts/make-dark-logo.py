#!/usr/bin/env python3
"""Derive the dark-theme logo from the supplied artwork.

The delivered mark is navy (#164194) with red (#E63322) accents on
transparency. Navy scores about 1.8:1 against the dark theme's surface, so the
wordmark is redrawn in white for dark backgrounds while the red squares stay —
that keeps the mark recognisable without the white plate a raw drop-in needs.

Alpha is copied pixel for pixel, so the anti-aliased edges survive untouched.

    python3 scripts/make-dark-logo.py
"""
from pathlib import Path

from PIL import Image

SRC = Path("src/assets/afranet-logo.webp")
DST = Path("src/assets/afranet-logo-dark.webp")

WORDMARK_ON_DARK = (255, 255, 255)  # navy becomes white
ACCENT_ON_DARK = (255, 75, 56)      # brand red, lifted just enough for a dark ground


def main() -> None:
    src = Image.open(SRC).convert("RGBA")
    out = Image.new("RGBA", src.size)
    sp, op = src.load(), out.load()

    for y in range(src.height):
        for x in range(src.width):
            r, g, b, a = sp[x, y]
            if a == 0:
                op[x, y] = (0, 0, 0, 0)
                continue
            # Two inks only: whichever channel leads decides which family the
            # pixel belongs to, so anti-aliased tones follow their own colour.
            ink = ACCENT_ON_DARK if r > b else WORDMARK_ON_DARK
            op[x, y] = (*ink, a)

    out.save(DST, format="WEBP", lossless=True, quality=100)
    print(f"{DST}  {DST.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
