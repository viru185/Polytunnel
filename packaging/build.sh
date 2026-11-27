#!/usr/bin/env bash
# Builds Polytunnel's installers from already-built release binaries.
#
#   packaging/build.sh <target> <version> [outdir]
#
# <target>: x86_64-pc-windows-msvc, aarch64-pc-windows-msvc, x86_64-unknown-linux-gnu,
#           aarch64-unknown-linux-gnu or universal-apple-darwin.
# Needs: cargo-about (unless NOTICES names a ready THIRD-PARTY-NOTICES.txt), dotnet
#        (Windows: WiX via `dotnet tool restore`), cargo-deb and cargo-generate-rpm (Linux),
#        pkgbuild/iconutil (macOS).
set -euo pipefail

target=$1
version=$2
mkdir -p "${3:-dist}"
out=$(cd "${3:-dist}" && pwd)
bin="target/$target/release"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Pinned Wintun release (official signed DLLs), checked against its SHA-256.
WINTUN_URL=https://www.wintun.net/builds/wintun-0.14.1.zip
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

sha256() {
    if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# Windows tools (dotnet, cargo, 7z) want C:/... paths, not Git Bash's /c/... ones.
native() {
    if command -v cygpath > /dev/null; then cygpath -m "$1"; else printf '%s
' "$1"; fi
}

notices="$work/THIRD-PARTY-NOTICES.txt"
if [ -n "${NOTICES:-}" ]; then
    cp "$NOTICES" "$notices"
else
    cargo about generate --fail packaging/about.hbs -o "$(native "$notices")"
fi

windows() {
    local arch dll
    case "$target" in
        x86_64-*) arch=x64 dll=amd64 ;;
        aarch64-*) arch=arm64 dll=arm64 ;;
        *) echo "unsupported Windows target $target" >&2; exit 1 ;;
    esac
    curl -sSfL -o "$work/wintun.zip" "$WINTUN_URL"
    echo "$WINTUN_SHA256  $work/wintun.zip" | sha256 -c -
    unzip -q "$work/wintun.zip" -d "$work"

    dotnet tool restore > /dev/null
    dotnet wix build packaging/windows/Polytunnel.wxs -arch "$arch" \
        -d "Version=$version" -d "BinDir=$bin" \
        -d "WintunDll=$work/wintun/bin/$dll/wintun.dll" \
        -d "WintunLicense=$work/wintun/LICENSE.txt" \
        -d "NoticesFile=$notices" \
        -o "$out/polytunnel-$version-windows-$arch.msi"
    rm -f "$out"/*.wixpdb

    # Portable zip (run polytunnel-daemon.exe install as administrator to register the service).
    local stage="$work/polytunnel"
    mkdir -p "$stage"
    cp "$bin/polytunnel.exe" "$bin/polytunnel-daemon.exe" "$bin/polytunnel-sso.exe"         "$work/wintun/bin/$dll/wintun.dll" "$stage/"
    cp LICENSE "$stage/LICENSE.txt"
    cp README.md "$notices" "$stage/"
    cp "$work/wintun/LICENSE.txt" "$stage/wintun-LICENSE.txt"
    (cd "$work" && 7z a -tzip "$(native "$out/polytunnel-$version-windows-$arch.zip")" polytunnel > /dev/null)
}

linux() {
    local arch
    case "$target" in
        x86_64-*) arch=amd64 ;;
        aarch64-*) arch=arm64 ;;
        *) echo "unsupported Linux target $target" >&2; exit 1 ;;
    esac
    cargo deb --no-build --no-strip --target "$target" --deb-version "$version" \
        -o "$out/polytunnel_${version}_$arch.deb"
    cargo generate-rpm --target "$target" --set-metadata "version = \"$version\"" -o "$out/"
    local stage="$work/polytunnel"
    mkdir -p "$stage"
    cp "$bin/polytunnel" "$bin/polytunnel-daemon" README.md LICENSE "$notices" "$stage/"
    cp packaging/linux/polytunnel-daemon.service packaging/linux/polytunnel.desktop "$stage/"
    tar -C "$work" -czf "$out/polytunnel-$version-linux-$arch.tar.gz" polytunnel
}

macos() {
    local app="$work/root/Applications/Polytunnel.app/Contents"
    mkdir -p "$app/MacOS" "$app/Resources" "$work/root/Library/LaunchDaemons"
    cp "$bin/polytunnel" "$bin/polytunnel-daemon" "$bin/polytunnel-sso" "$app/MacOS/"
    sed "s/@VERSION@/$version/g" packaging/macos/Info.plist > "$app/Info.plist"
    cp LICENSE "$notices" "$app/Resources/"
    # Icon set from the PNG master.
    local iconset="$work/polytunnel.iconset"
    mkdir -p "$iconset"
    for size in 16 32 128 256; do
        sips -z $size $size assets/polytunnel.png --out "$iconset/icon_${size}x${size}.png" > /dev/null
        sips -z $((size * 2)) $((size * 2)) assets/polytunnel.png --out "$iconset/icon_${size}x${size}@2x.png" > /dev/null
    done
    iconutil -c icns "$iconset" -o "$app/Resources/polytunnel.icns"
    cp packaging/macos/com.github.viru185.polytunnel.daemon.plist "$work/root/Library/LaunchDaemons/"
    chmod +x packaging/macos/scripts/preinstall packaging/macos/scripts/postinstall
    # Developer ID signing, when the release workflow provides the identities.
    local sign_pkg=()
    if [ -n "${MACOS_APP_IDENTITY:-}" ]; then
        for exe in polytunnel-daemon polytunnel-sso; do
            codesign --force --options runtime --timestamp --sign "$MACOS_APP_IDENTITY" "$app/MacOS/$exe"
        done
        codesign --force --options runtime --timestamp --sign "$MACOS_APP_IDENTITY" \
            "$work/root/Applications/Polytunnel.app"
    fi
    if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
        sign_pkg=(--sign "$MACOS_INSTALLER_IDENTITY" --timestamp)
    fi
    pkgbuild --root "$work/root" --identifier com.github.viru185.polytunnel --version "$version" \
        --scripts packaging/macos/scripts --install-location / "${sign_pkg[@]}" \
        "$out/polytunnel-$version-macos-universal.pkg"
}

case "$target" in
    *-windows-msvc) windows ;;
    *-linux-gnu) linux ;;
    universal-apple-darwin) macos ;;
    *) echo "unsupported target $target" >&2; exit 1 ;;
esac

(cd "$out" && for f in *; do case "$f" in *.sha256) ;; *) sha256 "$f" > "$f.sha256" ;; esac; done)
ls -l "$out"
