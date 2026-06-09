#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# Package script for zelynic releases
# Creates tar.gz archives with proper structure for GitHub Releases

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    printf "${CYAN}→${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}⚠${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}✗${NC} %s\n" "$1" >&2
}

# Get version from Cargo.toml
get_version() {
    VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)
    echo "$VERSION"
}

# Build for a specific target
build_target() {
    local target="$1"
    local arch_name="$2"

    log_info "Building for $target..."

    # Add target if not exists
    rustup target add "$target" 2>/dev/null || true

    # Build
    cargo build --release --target "$target" 2>&1 | tail -5

    # Check if binary is static
    local binary_path="target/${target}/release/zelynic"
    if [[ "$target" == *"musl"* ]]; then
        if ldd "$binary_path" 2>&1 | grep -q "statically linked"; then
            log_success "Binary is statically linked"
        else
            log_warn "Binary may not be fully static"
        fi
    fi

    echo "$binary_path"
}

# Create tar.gz archive
create_archive() {
    local version="$1"
    local arch_name="$2"
    local binary_path="$3"

    local pkg_name="zelynic-v${version}-${arch_name}"
    local pkg_dir="dist/${pkg_name}"

    log_info "Creating archive: ${pkg_name}.tar.gz"

    # Create package directory structure
    rm -rf "$pkg_dir"
    install -dm755 "$pkg_dir"
    install -dm755 "$pkg_dir/man"

    # Copy binary
    install -m755 "$binary_path" "$pkg_dir/zelynic"

    # Copy documentation
    install -m644 README.md "$pkg_dir/"
    install -m644 LICENSE "$pkg_dir/"

    # Generate man page if possible
    if command -v zelynic >/dev/null 2>&1 || [ -f "$binary_path" ]; then
        log_info "Generating man page..."
        "$binary_path" man > "$pkg_dir/man/zelynic.1" 2>/dev/null || {
            # Fallback: create basic man page
            cat > "$pkg_dir/man/zelynic.1" << 'EOF'
.TH ZELYNIC 1 "2024" "zelynic" "User Commands"
.SH NAME
zelynic \- Easy userspace bandwidth manager for Linux
.SH SYNOPSIS
.B zelynic
[\fIOPTIONS\fR] [\fICOMMAND\fR]
.SH DESCRIPTION
zelynic provides a simple CLI interface for monitoring and limiting
per-process network bandwidth on Linux systems.
.SH COMMANDS
.TP
.B list
List network bandwidth usage per process
.TP
.B strict
Apply bandwidth limit to a process
.TP
.B remove
Remove bandwidth limit from a process
.TP
.B status
Show active bandwidth limits
.TP
.B clean
Clean up stale limits and state
.TP
.B completions
Generate shell completions
.TP
.B man
Generate man page
.TP
.B log
Historical bandwidth tracking
.TP
.B profile
Manage bandwidth profiles
.TP
.B qos
Quality of Service priority shaping
.TP
.B auto
Auto-throttle background daemon
.SH OPTIONS
.TP
.B \-\-help
Print help information
.TP
.B \-\-version
Print version information
.TP
.B \-\-no\-color
Disable colored output
.TP
.B \-\-iface \fIINTERFACE\fR
Network interface to use
.SH EXAMPLES
.TP
List processes:
.B sudo zelynic list
.TP
Limit download to 1MB/s:
.B sudo zelynic strict -d 1mb firefox
.TP
Monitor live bandwidth:
.B sudo zelynic list --live
.TP
Set high priority:
.B sudo zelynic qos high brave
.SH SEE ALSO
.BR tc (8),
.BR cgexec (1),
.BR ss (8)
.SH AUTHOR
Written by rezky_nightky (oxyzenQ) <with.rezky@gmail.com>.
.SH LICENSE
GPL-3.0
EOF
        }
        gzip -f "$pkg_dir/man/zelynic.1"
        log_success "Man page created"
    fi

    # Create archive
    local archive_name="${pkg_name}.tar.gz"
    tar -czf "dist/${archive_name}" -C dist "$pkg_name"

    # Generate SHA256
    cd dist
    sha256sum "$archive_name" > "${archive_name}.sha256"
    cd ..

    log_success "Archive created: dist/${archive_name}"

    # Cleanup
    rm -rf "$pkg_dir"

    echo "dist/${archive_name}"
}

# Main packaging function
main() {
    VERSION=$(get_version)
    log_info "Packaging zelynic v${VERSION}"

    # Create dist directory
    install -dm755 dist

    # Build for each target
    log_info "=== Building x86_64 (glibc) ==="
    BIN_X64=$(build_target "x86_64-unknown-linux-gnu" "x86_64-linux")
    ARCHIVE_X64=$(create_archive "$VERSION" "x86_64-linux" "$BIN_X64")

    log_info "=== Building x86_64 (musl - static) ==="
    BIN_MUSL=$(build_target "x86_64-unknown-linux-musl" "x86_64-linux-musl")
    ARCHIVE_MUSL=$(create_archive "$VERSION" "x86_64-linux-musl" "$BIN_MUSL")

    # Try to build for aarch64 if possible
    if rustup target add aarch64-unknown-linux-gnu 2>/dev/null; then
        log_info "=== Building aarch64 ==="
        if cargo build --release --target aarch64-unknown-linux-gnu 2>&1; then
            BIN_ARM=$(build_target "aarch64-unknown-linux-gnu" "aarch64-linux")
            ARCHIVE_ARM=$(create_archive "$VERSION" "aarch64-linux" "$BIN_ARM")
        else
            log_warn "aarch64 build failed (may need cross-compilation tools)"
        fi
    fi

    echo
    log_success "Packaging complete!"
    echo
    echo "  Archives in dist/:"
    ls -lh dist/*.tar.gz | awk '{print "    " $9 " (" $5 ")"}'
    echo
    echo "  SHA256 checksums:"
    cat dist/*.sha256 | while read line; do
        echo "    $line"
    done
    echo
    echo "  ${CYAN}Ready for GitHub Release${NC}"
}

main "$@"
