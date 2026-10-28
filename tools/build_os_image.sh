#!/bin/bash
# Build a SeedSigner OS image with this fork baked in and USB mass storage enabled.
#
# Usage:
#   tools/build_os_image.sh [pi0|pi02w|both]
#
# Clones seedsigner-os at the pinned commit if SEEDSIGNER_OS_DIR is unset,
# applies os-patches/0001-usb-mass-storage-for-encrypted-backup.patch, and
# runs opt/build.sh. The image is written under the OS checkout's images/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-pi0}"
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

build_one() {
  local board="$1"
  echo "Building ${board} from ${ROOT}"
  (
    cd "${OS_DIR}/opt"
    ./build.sh "--${board}" --app-repo="${ROOT}" --app-branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD)"
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
