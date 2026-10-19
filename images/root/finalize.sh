#!/bin/sh
set -eu
# Locked account aging metadata must not depend on the build calendar date.
days=$((1792281600 / 86400))
awk -F: -v OFS=: -v days="$days" '{ if ($3 ~ /^[0-9]+$/) $3=days; print }' "$BUILDROOT/etc/shadow" > "$BUILDROOT/etc/shadow.normalized"
chmod 0600 "$BUILDROOT/etc/shadow.normalized"
mv "$BUILDROOT/etc/shadow.normalized" "$BUILDROOT/etc/shadow"
rm -f "$BUILDROOT/var/lib/systemd/random-seed" "$BUILDROOT/var/lib/urandom/random-seed"
