#!/usr/bin/env python
"""Derives the Secenter icon sizes from the single source asset.

The logo is authored once and committed once. This script produces the two
derivatives that are actually consumed — nothing else — so the repository never
accumulates half a dozen near-identical copies of the same owl:

  secenter-icon-128.png  the VS Code manifest icon, and the size the Marketplace
                         publisher profile asks for.
  secenter-icon-256.png  what the webviews load. The nav mark renders at 28 px
                         and the dashboard mark slightly larger, so 256 covers a
                         3x display with room to spare.

The source is never modified, never cropped and never stretched. A source that
is not exactly square is padded with transparency rather than cut, because the
owl losing its ear tufts to a square crop is worse than a few transparent
pixels: VS Code requires a square icon, and that padding is the only concession
made to it.

Usage:
    python scripts/build-branding-assets.py [--source PATH] [--check]

`--check` verifies the derivatives are current without writing anything, which
is what CI would run.
"""

import argparse
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover - environment problem, not a code path
    sys.exit("Pillow is required: python -m pip install Pillow")

BRANDING_DIR = Path(__file__).resolve().parent.parent / "media" / "branding"
DEFAULT_SOURCE = BRANDING_DIR / "secenter-icon.png"

# The only sizes anything actually reads. Adding one here means a consumer for
# it exists; if nothing consumes it, it does not belong in the package.
DERIVATIVES = (128, 256)

# Beyond this, a source is not "roughly square" and padding it would letterbox
# the owl into a stamp. Better to say so than to silently produce a bad icon.
MAX_ASPECT_DEVIATION = 0.35


def square(image: Image.Image) -> Image.Image:
    """Returns a square image without cropping and without stretching."""
    width, height = image.size
    if width == height:
        return image
    side = max(width, height)
    padded = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    padded.paste(image, ((side - width) // 2, (side - height) // 2))
    return padded


def derive(source_path: Path, check_only: bool = False) -> int:
    if not source_path.is_file():
        sys.exit(
            f"Source asset not found: {source_path}\n"
            "Place the Secenter owl (square, transparent or white background) there first.\n"
            "It is the one file that is authored rather than generated."
        )

    with Image.open(source_path) as opened:
        source = opened.convert("RGBA")
        width, height = source.size
        deviation = abs(width - height) / max(width, height)
        if deviation > MAX_ASPECT_DEVIATION:
            sys.exit(
                f"Source is {width}x{height}: too far from square ({deviation:.0%} deviation).\n"
                "Padding it to square would shrink the owl inside a wide transparent field.\n"
                "Supply the icon-only (square) variant of the logo, not the full lockup."
            )
        if deviation:
            print(f"note: source is {width}x{height}, padded to square with transparency (never cropped)")

        canvas = square(source)
        stale = []
        for size in DERIVATIVES:
            target = BRANDING_DIR / f"secenter-icon-{size}.png"
            # LANCZOS is the highest-quality downscale Pillow offers, and the
            # result is deterministic: the same source always produces the same
            # bytes, so a rebuild never shows up as a spurious diff.
            resized = canvas.resize((size, size), Image.LANCZOS)
            if check_only:
                if not target.is_file():
                    stale.append(f"{target.name} is missing")
                    continue
                with Image.open(target) as existing:
                    if existing.size != (size, size):
                        stale.append(f"{target.name} is {existing.size[0]}x{existing.size[1]}, expected {size}x{size}")
                continue
            resized.save(target, "PNG", optimize=True)
            print(f"wrote {target.relative_to(BRANDING_DIR.parent.parent)} ({size}x{size}, {target.stat().st_size} bytes)")

        if check_only:
            for problem in stale:
                print(f"stale: {problem}")
            return 1 if stale else 0
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="Square owl source PNG")
    parser.add_argument("--check", action="store_true", help="Verify derivatives without writing")
    arguments = parser.parse_args()
    return derive(arguments.source, arguments.check)


if __name__ == "__main__":
    sys.exit(main())
