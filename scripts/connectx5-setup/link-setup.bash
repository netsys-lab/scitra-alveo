#!/usr/bin/env bash

set -euo pipefail

MST_DEV="/dev/mst/mt4119_pciconf1"
IFACE="enp129s0np0"
FEC_MODE="RS"        # match whatever RS-FEC sub-mode is enabled on the CMAC
LINK_TIMEOUT=10      # seconds to wait for carrier before giving up
POLL_INTERVAL=1      # seconds between carrier checks

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
fi

# Poll /sys/class/net/<iface>/carrier until it reads 1 (link up) or the timeout elapses.
wait_for_carrier() {
    local iface="$1" timeout="$2" elapsed=0
    local carrier_file="/sys/class/net/${iface}/carrier"

    echo -n "==> Waiting for carrier on $iface "
    while (( elapsed < timeout )); do
        if [[ -r "$carrier_file" ]] && [[ "$(cat "$carrier_file" 2>/dev/null)" == "1" ]]; then
            echo " up (after ${elapsed}s)"
            return 0
        fi
        sleep "$POLL_INTERVAL"
        elapsed=$(( elapsed + POLL_INTERVAL ))
        echo -n "."
    done
    echo " timed out after ${timeout}s"
    return 1
}

echo "==> Ensuring MST driver is running"
mst start || true

if [[ ! -e "$MST_DEV" ]]; then
    echo "MST device $MST_DEV not found." >&2
    echo "Run 'mst status -v' to find the correct device for this card." >&2
    exit 1
fi

echo
echo "==> Forcing link speed to 100G on $MST_DEV"
mlxlink -d "$MST_DEV" --speeds 100G --link_mode_force

echo
echo "==> Bringing up interface $IFACE"
ip link set dev "$IFACE" up

# The port must actually be link-up before --fec can be applied.
if ! wait_for_carrier "$IFACE" "$LINK_TIMEOUT"; then
    echo >&2
    echo "Link on $IFACE did not come up within ${LINK_TIMEOUT}s." >&2
    echo "Current mlxlink status for diagnosis:" >&2
    mlxlink -d "$MST_DEV" >&2 || true
    exit 1
fi

echo
echo "==> Configuring FEC ($FEC_MODE) on $MST_DEV"
mlxlink -d "$MST_DEV" --fec "$FEC_MODE"

echo
echo "==> Final link status"
mlxlink -d "$MST_DEV"

echo
echo "==> Interface status"
ip link show dev "$IFACE"

echo
echo Done.
