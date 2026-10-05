#!/bin/bash
set -euo pipefail

destination="/Applications/AWUS1900.app"
if [[ "$EUID" -ne 0 ]]; then
	echo "Run this script with sudo to remove $destination." >&2
	exit 1
fi
if [[ -d "$destination" ]]; then
	rm -rf "$destination"
	/usr/bin/killall AWUS1900MenuBar 2>/dev/null || true
	echo "Removed $destination"
else
	echo "$destination is not installed."
fi
