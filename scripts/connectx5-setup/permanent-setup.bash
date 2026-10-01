#!/usr/bin/env bash

set -euo pipefail

MST_DEV="/dev/mst/mt4119_pciconf1"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
fi

echo "==> Ensuring MST driver is running"
mst start || true   # harmless if already started

if [[ ! -e "$MST_DEV" ]]; then
    echo "MST device $MST_DEV not found." >&2
    echo "Run 'mst status -v' to find the correct device for this card." >&2
    exit 1
fi

echo
echo "==> Current settings on $MST_DEV"
mlxconfig -d "$MST_DEV" query | grep -E "LINK_TYPE_P1|PHY_AUTO_NEG_P1" || true

echo
echo "==> Writing persistent config: Ethernet mode + auto-negotiation disabled"
mlxconfig -d "$MST_DEV" -y set \
    LINK_TYPE_P1=ETH \
    PHY_AUTO_NEG_P1=AUTO_NEG_DISABLED

echo
echo "==> Pending settings (take effect after reset/reboot)"
mlxconfig -d "$MST_DEV" query | grep -E "LINK_TYPE_P1|PHY_AUTO_NEG_P1"

cat <<EOF

Done. These settings are stored in the NIC's non-volatile configuration store.
They are NOT active yet -- apply them with a firmware reset or a full reboot:
    sudo mlxfwreset -d $MST_DEV -y reset
EOF
