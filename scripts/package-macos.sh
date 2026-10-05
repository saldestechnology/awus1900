#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
bundle="$repo_root/build/AWUS1900.app"

make -C "$repo_root" all
rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Helpers"
cp "$repo_root/macos/Info.plist" "$bundle/Contents/Info.plist"
install -m 755 "$repo_root/rtlscan" "$bundle/Contents/Helpers/rtlscan"
install -m 755 "$repo_root/rtljoin" "$bundle/Contents/Helpers/rtljoin"

xcrun swiftc -O -parse-as-library -module-cache-path "$repo_root/build/swift-module-cache" \
	-target arm64-apple-macosx13.0 \
	-framework AppKit -framework Foundation -framework UniformTypeIdentifiers \
	"$repo_root/macos/AWUS1900MenuBar.swift" \
	-o "$bundle/Contents/MacOS/AWUS1900MenuBar"

codesign --force --deep --sign - "$bundle"
echo "Built $bundle"
