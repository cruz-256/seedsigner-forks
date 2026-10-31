"""In-memory seed for the viewer. Never written except as a KEF envelope."""

from __future__ import annotations


class ViewerState:
    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.mnemonic = ""
        self.passphrase = ""
        self.label = ""
        self.source = ""
        self.encryption_passphrase = ""
        self.file_bytes = b""
        self.compare_entropy = b""
        self.compare_fingerprint = ""

    @property
    def loaded(self) -> bool:
        return bool(self.mnemonic)


_state = ViewerState()


def get_viewer_state() -> ViewerState:
    return _state
