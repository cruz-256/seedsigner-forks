"""Draw the VIEWER mark. Signer images leave the picture unchanged."""

from __future__ import annotations

from PIL import Image, ImageDraw, ImageFont


def stamp_viewer(image: Image.Image) -> Image.Image:
    from seedsigner.variant import is_viewer

    if image is None or not is_viewer():
        return image
    if image.mode != "RGBA":
        stamped = image.convert("RGBA")
    else:
        stamped = image.copy()
    draw = ImageDraw.Draw(stamped)
    font = ImageFont.load_default()
    text = "VIEWER"
    box = draw.textbbox((0, 0), text, font=font)
    width = box[2] - box[0] + 6
    height = box[3] - box[1] + 4
    origin_x = max(0, stamped.width - width - 2)
    draw.rectangle((origin_x, 1, origin_x + width, 1 + height), fill=(0, 0, 0, 230))
    draw.text((origin_x + 3, 2), text, fill=(0, 255, 65, 255), font=font)
    if image.mode == "RGB":
        return stamped.convert("RGB")
    return stamped
