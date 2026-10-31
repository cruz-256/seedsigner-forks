"""Binary KEF QR codes: byte mode, error correction L, and a one-shot decoder."""

from __future__ import annotations

import qrcode

from seedsigner.models.kef import looks_like_envelope
from seedsigner.models.qr_type import DecodeQRStatus


def kef_qr_modules(payload: bytes) -> int:
    """Module count of a byte-mode QR at error correction L, quiet zone excluded."""
    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=0)
    code.add_data(payload)
    code.make(fit=True)
    return code.modules_count


class KefQRDecoder:
    """Accepts one QR whose payload is a raw KEF envelope."""

    def __init__(self):
        self.complete = False
        self.payload = b""

    def get_percent_complete(self, weight_mixed_frames: bool = False) -> int:
        return 100 if self.complete else 0

    def add_data(self, data) -> DecodeQRStatus:
        if isinstance(data, str):
            data = data.encode("latin-1")
        if not isinstance(data, (bytes, bytearray)):
            return DecodeQRStatus.INVALID
        raw = bytes(data)
        if looks_like_envelope(raw):
            self.payload = raw
            self.complete = True
            return DecodeQRStatus.COMPLETE
        return DecodeQRStatus.INVALID

    def add_image(self, image) -> DecodeQRStatus:
        try:
            from pyzbar.pyzbar import ZBarSymbol
            from pyzbar.pyzbar import decode as zbar_decode
        except Exception:
            return DecodeQRStatus.FALSE
        found = zbar_decode(image, symbols=[ZBarSymbol.QRCODE])
        if not found:
            return DecodeQRStatus.FALSE
        return self.add_data(found[0].data)


class TextQRDecoder:
    """Accepts one QR and keeps its text. Used to check an address."""

    def __init__(self):
        self.complete = False
        self.text = ""

    def get_percent_complete(self, weight_mixed_frames: bool = False) -> int:
        return 100 if self.complete else 0

    def add_data(self, data) -> DecodeQRStatus:
        if isinstance(data, (bytes, bytearray)):
            try:
                text = bytes(data).decode("utf-8").strip()
            except UnicodeError:
                return DecodeQRStatus.INVALID
        elif isinstance(data, str):
            text = data.strip()
        else:
            return DecodeQRStatus.INVALID
        if not text or len(text) > 120:
            return DecodeQRStatus.INVALID
        self.text = text
        self.complete = True
        return DecodeQRStatus.COMPLETE

    def add_image(self, image) -> DecodeQRStatus:
        try:
            from pyzbar.pyzbar import ZBarSymbol
            from pyzbar.pyzbar import decode as zbar_decode
        except Exception:
            return DecodeQRStatus.FALSE
        found = zbar_decode(image, symbols=[ZBarSymbol.QRCODE])
        if not found:
            return DecodeQRStatus.FALSE
        return self.add_data(found[0].data)
