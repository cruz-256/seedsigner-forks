"""Built-in SD slot backup files. The OS card is detected by its label or boot files."""

import json
from pathlib import Path

import pytest

from seedsigner.hardware.backup_volume import (
    OS_VOLUME_LABEL,
    BackupVolumeError,
    CardDirectory,
    fat_label_from_boot_sector,
    filename_for_label,
    request_slot_rescan,
)
from seedsigner.models.encrypted_backup import decrypt_seed_backup, encrypt_seed_backup


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _fat32_sector(label: str) -> bytes:
    sector = bytearray(512)
    sector[66] = 0x29
    raw = label.encode("ascii")[:11]
    sector[71:82] = raw + b" " * (11 - len(raw))
    return bytes(sector)


def test_fat_label_and_os_card_detection(tmp_path):
    assert fat_label_from_boot_sector(_fat32_sector("SEEDSIGNROS")) == "SEEDSIGNROS"
    card = CardDirectory(str(tmp_path), fat_label=OS_VOLUME_LABEL)
    assert card.is_os_card()
    blank = tmp_path / "blank"
    blank.mkdir()
    assert CardDirectory(str(blank), fat_label="BACKUP").is_os_card() is False
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "zImage").write_bytes(b"x")
    assert CardDirectory(str(boot)).is_os_card()


def test_write_read_wipe_round_trip(tmp_path):
    card = CardDirectory(str(tmp_path), fat_label="BACKUP")
    blob = encrypt_seed_backup(mnemonic=MNEMONIC, encryption_passphrase="correct horse", label="savings")
    name = card.write_kef(filename_for_label("savings"), blob)
    assert name == "savings.kef"
    assert decrypt_seed_backup(card.read_kef(name), "correct horse")["mnemonic"] == MNEMONIC
    card.wipe_kef(name)
    assert card.list_kef() == []
    with pytest.raises(BackupVolumeError):
        card.write_kef("zImage", blob)
    with pytest.raises(BackupVolumeError):
        card.write_kef("../evil.kef", blob)


def test_os_card_warning_is_not_a_write(tmp_path):
    """Backing out of the OS-card warning must not create a file. The view
    only calls write_kef after the confirm screen returns."""
    card = CardDirectory(str(tmp_path), fat_label=OS_VOLUME_LABEL)
    assert card.is_os_card()
    assert card.list_kef() == []


def test_krux_seeds_json_import(tmp_path):
    blob = encrypt_seed_backup(mnemonic=MNEMONIC, encryption_passphrase="correct horse", label="KEFecbID")
    payload = {"KEFecbID": {"b64_kef": __import__("base64").b64encode(blob).decode()}}
    (tmp_path / "seeds.json").write_text(json.dumps(payload), encoding="utf-8")
    found = CardDirectory(str(tmp_path)).list_krux_entries()
    assert found[0][0] == "KEFecbID"
    assert decrypt_seed_backup(found[0][1], "correct horse")["label"] == "KEFecbID"


def test_rescan_writes_sysfs(tmp_path):
    host = tmp_path / "class" / "mmc_host" / "mmc0"
    host.mkdir(parents=True)
    rescan = host / "rescan"
    rescan.write_text("", encoding="ascii")
    request_slot_rescan(str(tmp_path))
    assert rescan.read_text(encoding="ascii") == "1"
    assert Path(rescan).is_file()
