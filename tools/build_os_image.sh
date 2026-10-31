#!/bin/bash
# Build a Pi Zero SeedSigner OS image for this fork.
#
# Usage:
#   tools/build_os_image.sh [pi0] [signer|viewer]
#
# signer keeps embit and the full app. viewer deletes signing and seed-creation
# sources after the app is copied, and turns off the embit package.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-pi0}"
VARIANT="${2:-${SEEDSIGNER_VARIANT:-signer}}"
OS_DIR="${SEEDSIGNER_OS_DIR:-${ROOT}/../seedsigner-os}"
OS_COMMIT="c4cb767a00ace8edf5e9414450c2849e15958ad7"
PATCH="${ROOT}/os-patches/0001-usb-mass-storage-for-encrypted-backup.patch"

if [[ ! -d "${OS_DIR}/.git" ]]; then
  git clone https://github.com/SeedSigner/seedsigner-os.git "${OS_DIR}"
fi

git -C "${OS_DIR}" fetch --depth 1 origin "${OS_COMMIT}" || true
git -C "${OS_DIR}" checkout "${OS_COMMIT}"
git -C "${OS_DIR}" submodule update --init --depth 1

# Re-apply from a clean tree at the pinned commit. checkout already discarded
# local edits when the commit changed; reset keeps a dirty retry idempotent.
git -C "${OS_DIR}" reset --hard "${OS_COMMIT}"
git -C "${OS_DIR}" apply "${PATCH}"

# prepare_variant.py runs after the app repo is copied into the overlay.
python3 - << PY
from pathlib import Path
path = Path("${OS_DIR}/opt/build.sh")
text = path.read_text()
needle = "  write_version_json\n  delete_unnecessary_files\n"
insert = """  write_version_json
  if [ -n "\${SEEDSIGNER_VARIANT:-}" ]; then
    python3 "\${rootfs_overlay}/opt/tools/prepare_variant.py" "\${SEEDSIGNER_VARIANT}" "\${rootfs_overlay}/opt"
  fi
  delete_unnecessary_files
"""
if needle not in text:
    raise SystemExit("build.sh hook point not found")
path.write_text(text.replace(needle, insert, 1))
PY

if [[ "${VARIANT}" == "viewer" ]]; then
  DEFCONFIG="${OS_DIR}/opt/pi0/configs/pi0_defconfig"
  sed -i 's/^BR2_PACKAGE_PYTHON_EMBIT=y/# BR2_PACKAGE_PYTHON_EMBIT is not set/' "${DEFCONFIG}"
fi

build_one() {
  local board="$1"
  echo "Building ${board} variant ${VARIANT} from ${ROOT}"
  (
    cd "${OS_DIR}/opt"
    SEEDSIGNER_VARIANT="${VARIANT}" ./build.sh "--${board}" --app-repo="${ROOT}" --app-branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD)"
  )
}

case "${TARGET}" in
  pi0) build_one pi0 ;;
  pi02w) build_one pi02w ;;
  both)
    build_one pi0
    build_one pi02w
    ;;
  *)
    echo "Usage: $0 [pi0|pi02w|both]" >&2
    exit 2
    ;;
esac

echo "Images:"
ls -l "${OS_DIR}/images"/*.img || true
