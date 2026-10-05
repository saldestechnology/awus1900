#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
source_bundle="$repo_root/build/AWUS1900.app"
destination="/Applications/AWUS1900.app"

if [[ ! -d "$source_bundle" ]]; then
	echo "Build the app first with scripts/package-macos.sh" >&2
	exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
	echo "Run this script with sudo to install in /Applications." >&2
	exit 1
fi

ditto "$source_bundle" "$destination"
chown -R root:wheel "$destination"
echo "Installed $destination"
