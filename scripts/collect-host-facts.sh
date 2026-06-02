#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# collect-host-facts.sh — Read-only host capability collector for Zelynic.
#
# This script gathers information about the current host's kernel, distro,
# cgroup configuration, and required userspace tools. It is intentionally
# non-mutating: it never modifies nftables, tc, cgroups, systemd state,
# or runtime directories.
#
# No root/sudo is required. All operations are read-only.
#
set -euo pipefail

echo "========================================="
echo " Zelynic Host Fact Collector (read-only)"
echo "========================================="
echo ""

# --- Kernel / OS ---
echo "--- Kernel / OS ---"
if command -v uname &>/dev/null; then
    echo "uname -r:              $(uname -r)"
    echo "uname -s:              $(uname -s)"
    echo "uname -m:              $(uname -m)"
else
    echo "uname:                 not found"
fi

if [[ -f /etc/os-release ]]; then
    echo ""
    echo "--- /etc/os-release (summary) ---"
    # Print key fields
    for field in ID NAME VERSION_ID PRETTY_NAME; do
        val=$(grep "^${field}=" /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
        if [[ -n "$val" ]]; then
            printf "  %-14s %s\n" "${field}:" "$val"
        fi
    done
else
    echo "/etc/os-release:       not found"
fi

# --- cgroup ---
echo ""
echo "--- cgroup ---"
if [[ -f /proc/filesystems ]]; then
    cgroup_v2=$(grep -c '\bcgroup2\b' /proc/filesystems 2>/dev/null || true)
    cgroup_v1=$(grep -c '\bcgroup\b' /proc/filesystems 2>/dev/null || true)
    echo "cgroup v2 in /proc/filesystems:  ${cgroup_v2}"
    echo "cgroup v1 in /proc/filesystems:  ${cgroup_v1}"
fi

if command -v mount &>/dev/null; then
    echo ""
    echo "cgroup mounts:"
    mount 2>/dev/null | grep cgroup || echo "  (no cgroup mounts found)"
fi

# Try to infer cgroup mode from mountinfo
if [[ -f /proc/self/mountinfo ]]; then
    cgroup2_lines=$(grep -c 'cgroup2' /proc/self/mountinfo 2>/dev/null || true)
    cgroup1_lines=$(grep -c ' cgroup ' /proc/self/mountinfo 2>/dev/null || true)
    if [[ "$cgroup2_lines" -gt 0 && "$cgroup1_lines" -eq 0 ]]; then
        echo "Inferred cgroup mode:    pure cgroup v2"
    elif [[ "$cgroup2_lines" -gt 0 && "$cgroup1_lines" -gt 0 ]]; then
        echo "Inferred cgroup mode:    hybrid cgroup v1/v2"
    elif [[ "$cgroup1_lines" -gt 0 ]]; then
        echo "Inferred cgroup mode:    cgroup v1 only"
    else
        echo "Inferred cgroup mode:    unknown (no cgroup mounts detected)"
    fi
fi

# --- Userspace tools ---
echo ""
echo "--- Userspace tools ---"

check_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        local version
        version=$("$name" --version 2>&1 | head -1 || echo "(version unknown)")
        printf "  %-16s %s\n" "${name}:" "$version"
    else
        printf "  %-16s %s\n" "${name}:" "not found"
    fi
}

check_tool nft
check_tool tc
check_tool ip
check_tool ss
check_tool systemctl
check_tool systemd-run

# --- Default route interface ---
echo ""
echo "--- Default route ---"
if command -v ip &>/dev/null; then
    default_iface=$(ip route show default 2>/dev/null | head -1 | grep -oP 'dev \K\S+' || true)
    if [[ -n "$default_iface" ]]; then
        echo "Default interface:     ${default_iface}"
        # Show a bit more about it
        ip addr show dev "$default_iface" 2>/dev/null | head -3 || true
    else
        echo "Default interface:     (none detected)"
    fi
else
    echo "Default interface:     (ip command not available)"
fi

echo ""
echo "========================================="
echo " Collection complete. No changes were made."
echo "========================================="
