#!/bin/bash
# update-fingerprints.sh - Fetch latest fingerprint database

set -e

FINGERPRINT_URL="https://raw.githubusercontent.com/PwnedBytes/PwnJacker/main/configs/fingerprints.yaml"
DEST="configs/fingerprints.yaml"

echo "Downloading latest fingerprints from $FINGERPRINT_URL"
curl -s -o "$DEST" "$FINGERPRINT_URL"

if [ $? -eq 0 ]; then
    echo "✅ Fingerprints updated successfully"
else
    echo "❌ Failed to update fingerprints"
    exit 1
fi