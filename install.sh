#!/usr/bin/env bash
# Install Phaethon from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/arahe-dev/Phaethon/main/install.sh | bash
#
# This installs a versioned, checksummed binary from a release rather than
# building the default branch, so what lands on the machine is a build that was
# tested and tagged rather than whatever main happened to be that afternoon.
#
# It deliberately does not run as root. `phaethon setup` needs the invoking
# user's own environment: the config, the CA and the trust store all belong to
# that user, and running setup under sudo would install them for root instead.
# Elevation is used for exactly one thing, writing the binary to /usr/local/bin.
#
# Options:
#   --version <v>     install a specific tag instead of the latest release
#   --prefix <dir>    install somewhere other than /usr/local/bin
#   --no-setup        install the binary only; do not run setup
#   --no-verify       skip checksum verification (not recommended)
set -euo pipefail

REPO="arahe-dev/Phaethon"
OWNER_REPO="${PHAETHON_REPO:-$REPO}"
VERSION=""
PREFIX="/usr/local/bin"
RUN_SETUP=1
VERIFY=1

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --prefix)  PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
    --no-setup) RUN_SETUP=0; shift ;;
    --no-verify) VERIFY=0; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

# --- refuse the cases that produce a broken install -------------------------
[ "$(uname -s)" = "Linux" ] || die "this script installs the Linux build; use the installer or archive for your platform"

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  die "do not run this as root.
  setup creates a certificate authority and trust entry for the *invoking* user,
  so running it as root would configure the machine for root instead of for you.
  Run it as your normal user; elevation is requested only where it is needed."
fi

for tool in curl tar sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# --- resolve the release ----------------------------------------------------
if [ -z "$VERSION" ]; then
  say "finding the latest release"
  VERSION="$(curl -fsSL "https://api.github.com/repos/$OWNER_REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || die "no published release found; pass --version <tag> to install a specific one"
fi
say "version $VERSION"

ASSET="phaethon-linux-$ARCH.tar.gz"
BASE="https://github.com/$OWNER_REPO/releases/download/$VERSION"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say "downloading $ASSET"
curl -fsSL -o "$WORK/$ASSET" "$BASE/$ASSET" \
  || die "could not download $ASSET from release $VERSION"

# --- verify before installing ----------------------------------------------
# A curl-to-shell installer that skips this is trusting the transport and every
# hop on it. Verification is the difference between installing a release and
# installing whatever the network decided to send.
if [ "$VERIFY" -eq 1 ]; then
  if curl -fsSL -o "$WORK/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" 2>/dev/null; then
    expect="$(sed -n "s/^\([0-9a-f]\{64\}\)[[:space:]]\+$ASSET$/\1/p" "$WORK/SHA256SUMS.txt" | head -1)"
    if [ -z "$expect" ]; then
      die "$ASSET is not listed in the release's SHA256SUMS.txt"
    fi
    actual="$(sha256sum "$WORK/$ASSET" | cut -d' ' -f1)"
    if [ "$expect" != "$actual" ]; then
      die "checksum mismatch for $ASSET
  expected $expect
  actual   $actual
  The download did not match the published release. Nothing was installed."
    fi
    say "checksum verified"
  else
    die "could not fetch SHA256SUMS.txt, so the download cannot be verified.
  Re-run with --no-verify only if you have another way to trust the file."
  fi
fi

tar -xzf "$WORK/$ASSET" -C "$WORK"
BIN="$(find "$WORK" -maxdepth 2 -name phaethon -type f | head -1)"
[ -n "$BIN" ] || die "the archive did not contain a phaethon binary"

# --- install the binary (the only step that may need elevation) -------------
say "installing to $PREFIX/phaethon"
if [ -w "$PREFIX" ]; then
  install -m 0755 "$BIN" "$PREFIX/phaethon"
else
  say "  $PREFIX is not writable by you; asking for sudo for this one step"
  sudo install -m 0755 "$BIN" "$PREFIX/phaethon"
fi

"$PREFIX/phaethon" version || die "the installed binary does not run"

# --- setup, as the invoking user -------------------------------------------
if [ "$RUN_SETUP" -eq 0 ]; then
  say ""
  say "Installed. Finish with:"
  say "  phaethon setup"
  exit 0
fi

say ""
say "Running setup. It will ask before trusting a certificate, and will tell you"
say "if this desktop cannot be configured automatically."
say ""
"$PREFIX/phaethon" setup

say ""
say "Verifying"
"$PREFIX/phaethon" doctor || true

say ""
say "Done. If anything reported MANUAL, the daemon is still usable: point your"
say "applications at the proxy it printed."
