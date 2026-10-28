import os

import pytest

from seedsigner.hardware.backup_volume import (
    BACKUP_MOUNT_POINT,
    OS_CARD_MOUNT_POINT,
    BackupIOError,
    BootDeviceRefused,
    CmdResult,
    MemoryBlockSource,
    MountedBackup,
    NotSafeToRemove,
    Volume,
    boot_names_from_cmdline,
    boot_names_from_mounts,
    format_volume_label,
    mounted_backup,
    parent_disk,
    path_is_usb_mass_storage,
    scan_volumes,
    volume_is_eligible,
)
from seedsigner.models.encrypted_backup import decrypt_seed_backup, encrypt_seed_backup


def _usb_disk(name, partitions, realpath=None, driver="usb-storage", size=64 * 1024 * 1024):
    part_sizes = {}
    if isinstance(partitions, dict):
        part_sizes = partitions
    elif partitions:
        share = size // len(partitions)
        part_sizes = {part: share for part in partitions}
    return {
        "realpath": realpath or f"/sys/devices/platform/soc/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0/block/{name}",
        "driver": driver,
        "size": size,
        "partitions": part_sizes,
    }


def _source(mounts="", cmdline="", **disks):
    return MemoryBlockSource(disks, mounts=mounts, cmdline=cmdline)


def test_parent_disk_and_usb_path_detection():
    assert parent_disk("sda1") == "sda"
    assert parent_disk("sda") == "sda"
    assert parent_disk("mmcblk0p1") == "mmcblk0"
    assert parent_disk("mmcblk0") == "mmcblk0"
    assert parent_disk("nvme0n1p2") == "nvme0n1"
    assert path_is_usb_mass_storage("/sys/devices/usb1/1-1/host0", None) is True
    assert path_is_usb_mass_storage("/sys/devices/platform/mmc", None) is False
    assert path_is_usb_mass_storage("/sys/devices/platform/mmc", "usb-storage") is True
    assert path_is_usb_mass_storage("/sys/devices/platform/mmc", "uas") is True


def test_boot_names_from_mounts_and_cmdline():
    mounts = "\n".join([
        "/dev/mmcblk0p1 /mnt/microsd vfat ro 0 0",
        "/dev/root / ext2 rw 0 0",
        "/dev/sda2 /boot/firmware vfat rw 0 0",
        "tmpfs /tmp tmpfs rw 0 0",
    ])
    assert boot_names_from_mounts(mounts) == {"mmcblk0p1", "mmcblk0", "sda2", "sda"}
    assert boot_names_from_cmdline("console=tty1 root=/dev/mmcblk0p2 rootwait") == {"mmcblk0p2", "mmcblk0"}
    assert boot_names_from_cmdline("root=PARTUUID=deadbeef quiet") == set()


def test_onboard_sd_and_non_usb_are_never_eligible():
    source = _source(
        mounts=f"/dev/mmcblk0p1 {OS_CARD_MOUNT_POINT} vfat rw 0 0\n",
        mmcblk0=_usb_disk("mmcblk0", {"mmcblk0p1": 32 * 1024 * 1024}, driver="mmc"),
        sda=_usb_disk("sda", {"sda1": 8 * 1024 * 1024}),
        vda=_usb_disk("vda", {"vda1": 8 * 1024 * 1024}, realpath="/sys/devices/virtio/block/vda", driver="virtio"),
    )
    # Even if the onboard slot is mis-labeled as USB, the mmcblk name is refused.
    source.disks["mmcblk0"]["driver"] = "usb-storage"
    source.disks["mmcblk0"]["realpath"] = "/sys/devices/usb1/1-1/block/mmcblk0"
    scan = scan_volumes(source)
    assert [volume.dev_node for volume in scan.eligible] == ["/dev/sda1"]
    assert "/dev/mmcblk0p1" in scan.refused_boot
    assert volume_is_eligible(Volume("mmcblk0", "mmcblk0p1", "/dev/mmcblk0p1", True, False, 1)) is False
    assert volume_is_eligible(Volume("sda", "sda1", "/dev/sda1", True, True, 1)) is False
    assert volume_is_eligible(Volume("sda", "sda1", "/dev/sda1", False, False, 1)) is False


def test_usb_boot_device_is_refused():
    source = _source(
        mounts="/dev/fakeusb1 / ext4 rw 0 0\n",
        cmdline="root=/dev/fakeusb1",
        fakeusb=_usb_disk("fakeusb", {"fakeusb1": 1024}),
    )
    scan = scan_volumes(source)
    assert scan.eligible == []
    assert scan.refused_boot == ["/dev/fakeusb1"]


def test_partitioned_usb_disk_offers_partitions_not_the_raw_device():
    source = _source(
        sda=_usb_disk("sda", {"sda1": 1024, "sda2": 2048}),
    )
    names = [volume.volume_name for volume in scan_volumes(source).eligible]
    assert names == ["sda1", "sda2"]


def test_unpartitioned_usb_disk_is_eligible():
    source = _source(sda=_usb_disk("sda", {}))
    scan = scan_volumes(source)
    assert [volume.dev_node for volume in scan.eligible] == ["/dev/sda"]
    assert "GB" in format_volume_label(scan.eligible[0]) or "MB" in format_volume_label(scan.eligible[0])


def test_mount_is_not_attempted_for_boot_device(tmp_path):
    source = _source(
        mounts=f"/dev/mmcblk0p1 {OS_CARD_MOUNT_POINT} vfat rw 0 0\n",
        mmcblk0=_usb_disk("mmcblk0", {"mmcblk0p1": 1024}, driver="mmc", realpath="/sys/devices/mmc"),
        sda=_usb_disk("sda", {"sda1": 1024}),
    )
    calls = []

    def runner(argv):
        calls.append(argv)
        return CmdResult(0)

    with pytest.raises(BootDeviceRefused):
        with mounted_backup(
            "/dev/mmcblk0p1",
            read_only=False,
            source=source,
            runner=runner,
            mount_point=str(tmp_path),
        ):
            raise AssertionError("must not enter the write body")
    assert calls == []
    with pytest.raises(BootDeviceRefused):
        with mounted_backup(
            "/dev/../mnt/microsd",
            read_only=False,
            source=source,
            runner=runner,
            mount_point=str(tmp_path),
        ):
            pass
    assert calls == []


def test_refuses_to_mount_the_os_card_mount_point():
    source = _source(sda=_usb_disk("sda", {"sda1": 1024}))

    def runner(argv):
        raise AssertionError(argv)

    with pytest.raises(BootDeviceRefused):
        with mounted_backup("/dev/sda1", read_only=False, source=source, runner=runner, mount_point=OS_CARD_MOUNT_POINT):
            pass
    with pytest.raises(BootDeviceRefused):
        with mounted_backup("/dev/sda1", read_only=False, source=source, runner=runner, mount_point="/"):
            pass
    assert BACKUP_MOUNT_POINT != OS_CARD_MOUNT_POINT


def test_export_and_import_round_trip_on_a_fake_usb_volume(tmp_path):
    mount_point = tmp_path / "card"
    mount_point.mkdir()
    source = _source(fakeusb=_usb_disk("fakeusb", {"fakeusb1": 8 * 1024 * 1024}))
    dev = "/dev/fakeusb1"

    def runner(argv):
        if argv[0] == "mount":
            assert argv[:3] == ["mount", "-o", "sync,noatime"]
            source.mounts = f"{dev} {mount_point} vfat rw,sync 0 0\n"
            return CmdResult(0)
        if argv[0] == "umount":
            source.mounts = ""
            return CmdResult(0)
        raise AssertionError(argv)

    blob = encrypt_seed_backup(
        mnemonic="obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash",
        seed_type="bip39",
        seed_passphrase="",
        include_seed_passphrase=False,
        encryption_passphrase="volume-round-trip",
        scrypt_n=1 << 4,
        scrypt_r=1,
        scrypt_p=1,
    )
    with mounted_backup(dev, read_only=False, source=source, runner=runner, mount_point=str(mount_point)) as mounted:
        written = mounted.write_backup_file("seedsigner-backup-test.ssenc", blob)
    assert written == "seedsigner-backup-test.ssenc"
    assert source.mounts == ""
    assert (mount_point / written).read_bytes() == blob

    # A second write of the same name must not overwrite the first file.
    with mounted_backup(dev, read_only=False, source=source, runner=runner, mount_point=str(mount_point)) as mounted:
        second = mounted.write_backup_file("seedsigner-backup-test.ssenc", b"ssenc-placeholder-not-used")
    assert second == "seedsigner-backup-test-2.ssenc"

    calls = []

    def ro_runner(argv):
        calls.append(argv)
        if argv[0] == "mount":
            source.mounts = f"{dev} {mount_point} vfat ro 0 0\n"
            return CmdResult(0)
        if argv[0] == "umount":
            source.mounts = ""
            return CmdResult(0)
        raise AssertionError(argv)

    with mounted_backup(dev, read_only=True, source=source, runner=ro_runner, mount_point=str(mount_point)) as mounted:
        assert mounted.list_backup_files() == [
            "seedsigner-backup-test-2.ssenc",
            "seedsigner-backup-test.ssenc",
        ]
        loaded = mounted.read_backup_file("seedsigner-backup-test.ssenc", max_bytes=len(blob) + 10)
    assert calls[0][:3] == ["mount", "-o", "ro,noatime"]
    assert source.mounts == ""
    payload = decrypt_seed_backup(loaded, "volume-round-trip")
    assert payload["mnemonic"].startswith("obscure bone")


def test_unmount_failure_is_not_safe_to_remove(tmp_path):
    source = _source(fakeusb=_usb_disk("fakeusb", {"fakeusb1": 1024}))

    def runner(argv):
        if argv[0] == "mount":
            source.mounts = f"/dev/fakeusb1 {tmp_path} vfat rw 0 0\n"
            return CmdResult(0)
        if argv[0] == "umount":
            return CmdResult(1, stderr="target is busy")
        raise AssertionError(argv)

    with pytest.raises(NotSafeToRemove):
        with mounted_backup(
            "/dev/fakeusb1",
            read_only=False,
            source=source,
            runner=runner,
            mount_point=str(tmp_path),
        ) as mounted:
            mounted.write_backup_file("seedsigner-backup-x.ssenc", b"abc")


def test_mount_source_mismatch_is_refused(tmp_path):
    source = _source(fakeusb=_usb_disk("fakeusb", {"fakeusb1": 1024}))

    def runner(argv):
        if argv[0] == "mount":
            # The kernel mounted a different node than the one we asked for.
            source.mounts = f"/dev/mmcblk0p1 {tmp_path} vfat rw 0 0\n"
            return CmdResult(0)
        if argv[0] == "umount":
            source.mounts = ""
            return CmdResult(0)
        raise AssertionError(argv)

    with pytest.raises(BootDeviceRefused):
        with mounted_backup(
            "/dev/fakeusb1",
            read_only=False,
            source=source,
            runner=runner,
            mount_point=str(tmp_path),
        ):
            raise AssertionError("must not write")


def test_path_escape_and_oversize_read_are_refused(tmp_path):
    mounted = MountedBackup(str(tmp_path))
    with pytest.raises(BackupIOError):
        mounted.write_backup_file("../escape.ssenc", b"nope")
    (tmp_path / "ok.ssenc").write_bytes(b"12345")
    with pytest.raises(BackupIOError):
        mounted.read_backup_file("ok.ssenc", max_bytes=4)
    assert mounted.read_backup_file("ok.ssenc", max_bytes=5) == b"12345"
    assert os.path.basename(BACKUP_MOUNT_POINT) == "seedsigner-backup"
