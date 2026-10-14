#!/bin/sh
# install.sh — install the `peek` CLI from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/andras-tkcs/peek/main/install.sh | sh
#
# Environment overrides:
#   PEEK_VERSION       release tag to install (default: latest)
#   PEEK_INSTALL_DIR   install directory (default: /usr/local/bin, else ~/.local/bin)
#
# Installs only the consumer CLI (`peek`). To run a server, grab `peekd` from the
# releases page or build from source — see the peek-server skill / README.
set -eu

REPO="andras-tkcs/peek"
BIN="peek"

err() { echo "install.sh: $*" >&2; exit 1; }

# --- detect platform -----------------------------------------------------------
os=$(uname -s)
case "$os" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) err "unsupported OS '$os'. Windows: download the .zip from https://github.com/$REPO/releases" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)   arch=amd64 ;;
  arm64|aarch64)  arch=arm64 ;;
  *) err "unsupported architecture '$arch'" ;;
esac

# --- resolve version -----------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch <url> -> stdout
  if have curl; then curl -fsSL "$1"
  elif have wget; then wget -qO- "$1"
  else err "need curl or wget"; fi
}

download() { # download <url> <dest>
  if have curl; then curl -fsSL -o "$2" "$1"
  elif have wget; then wget -qO "$2" "$1"
  else err "need curl or wget"; fi
}

version="${PEEK_VERSION:-}"
if [ -z "$version" ]; then
  version=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$version" ] || err "could not resolve the latest release; set PEEK_VERSION"
fi
case "$version" in
  v[0-9]*) ;;
  *) err "invalid version '$version' (expected a release tag like v1.2.3)" ;;
esac
case "$version" in
  *[!A-Za-z0-9._-]*) err "invalid version '$version'" ;;
esac

name="peek_${version}_${os}_${arch}"
url="https://github.com/$REPO/releases/download/${version}/${name}.tar.gz"

# --- download, verify & extract ------------------------------------------------
sums_url="https://github.com/$REPO/releases/download/${version}/checksums.txt"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t peek)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $name ..."
download "$url" "$tmp/${name}.tar.gz" || err "download failed: $url"
download "$sums_url" "$tmp/checksums.txt" \
  || err "download failed: $sums_url (releases published before checksums.txt existed cannot be verified; pick a newer PEEK_VERSION)"

awk -v f="${name}.tar.gz" '$2 == f || $2 == "*" f' "$tmp/checksums.txt" > "$tmp/expected.sha256"
[ "$(wc -l < "$tmp/expected.sha256" | tr -d ' ')" = "1" ] \
  || err "checksums.txt has no single entry for ${name}.tar.gz"

if have sha256sum; then
  (cd "$tmp" && sha256sum -c expected.sha256 >/dev/null 2>&1) \
    || err "checksum mismatch for ${name}.tar.gz; refusing to install"
elif have shasum; then
  (cd "$tmp" && shasum -a 256 -c expected.sha256 >/dev/null 2>&1) \
    || err "checksum mismatch for ${name}.tar.gz; refusing to install"
else
  err "need sha256sum or shasum to verify the download"
fi
echo "Verified SHA-256 checksum."

tar -xzf "$tmp/${name}.tar.gz" -C "$tmp" || err "extract failed"

src="$tmp/$name/$BIN"
[ -f "$src" ] || src="$tmp/$BIN"          # tolerate a flat archive layout
[ -f "$src" ] || err "could not find '$BIN' in the archive"

# --- install -------------------------------------------------------------------
dir="${PEEK_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then dir=/usr/local/bin
  else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"

dest="$dir/$BIN"
if mv "$src" "$dest" 2>/dev/null; then :
elif have sudo && [ -z "${PEEK_INSTALL_DIR:-}" ]; then
  echo "Installing to $dir (needs sudo) ..."
  sudo mv "$src" "$dest"
else
  err "cannot write to $dir; set PEEK_INSTALL_DIR to a writable directory"
fi
chmod +x "$dest" 2>/dev/null || true

echo "Installed $BIN $version -> $dest"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not on your PATH. Add it, e.g.:"
     echo "  export PATH=\"$dir:\$PATH\"" ;;
esac

echo "Next: peek login --host <your-peek-server>"
