"""In-memory state for one encrypted-backup export or import.

The encryption passphrase and file bytes live here instead of on View
arguments, because the controller logs destination arguments. Call ``clear``
when the flow ends, and the home screen clears this again as a backstop.
The seed itself, once the user loads it, lives in the normal in-memory seed
list. This object never writes a file.
"""

from __future__ import annotations


class BackupFlowState:
    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.encryption_passphrase = ""
        self.include_seed_passphrase = False
        self.seed = None
        self.volume_dev_node = ""
        self.volume_label = ""
        if isinstance(self.__dict__.get("file_bytes"), bytearray):
            for index in range(len(self.file_bytes)):
                self.file_bytes[index] = 0
        self.file_bytes = b""
        self.filename = ""


_state = BackupFlowState()


def get_backup_flow_state() -> BackupFlowState:
    return _state
