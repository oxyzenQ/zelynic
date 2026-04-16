#!/bin/sh
# oxy install script
# Usage: curl -fsSL https://raw.githubusercontent.com/oxyzenq/oxy/main/install.sh | sh
#
# This script detects architecture, downloads the latest release from GitHub,
# verifies SHA256 checksum, and installs oxy to /usr/local/bin/.

set -e

# Colors (only if stdout is a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    DIM='\033[2m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    DIM=''
    NC=''
fi

# Configuration
REPO="oxyzenq/oxy"
INSTALL_DIR="/usr/local/bin"
MAN_DIR="/usr/local/share/man/man1"

# Print functions
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

# Check if running as root for system-wide install
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "Not running as root. Installation will use sudo."
        SUDO="sudo"
    else
        SUDO=""
    fi
}

# Detect system architecture
detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        armv7l|armhf)
            ARCH="armv7"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            log_info "Supported: x86_64, aarch64, armv7"
            exit 1
            ;;
    esac
    log_info "Detected architecture: $ARCH"
}

# Get latest release version from GitHub API
get_latest_version() {
    log_info "Fetching latest release..."

    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        log_error "Failed to get latest version from GitHub"
        exit 1
    fi

    # Remove 'v' prefix if present
    VERSION=$(echo "$VERSION" | sed 's/^v//')
    log_info "Latest version: $VERSION"
}

# Download and extract
download_release() {
    ARCHIVE_NAME="oxy-v${VERSION}-${ARCH}-linux.tar.gz"
    URL="https://github.com/$REPO/releases/download/v${VERSION}/${ARCHIVE_NAME}"
    SHA_URL="${URL}.sha256"

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    log_info "Downloading $ARCHIVE_NAME..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$TMP_DIR/$ARCHIVE_NAME" || {
            log_error "Failed to download archive"
            exit 1
        }
        curl -fsSL "$SHA_URL" -o "$TMP_DIR/${ARCHIVE_NAME}.sha256" 2>/dev/null || {
            log_warn "SHA256 file not found, skipping verification"
            SKIP_VERIFY=1
        }
    else
        wget -q "$URL" -O "$TMP_DIR/$ARCHIVE_NAME" || {
            log_error "Failed to download archive"
            exit 1
        }
        wget -q "$SHA_URL" -O "$TMP_DIR/${ARCHIVE_NAME}.sha256" 2>/dev/null || {
            log_warn "SHA256 file not found, skipping verification"
            SKIP_VERIFY=1
        }
    fi

    # Verify SHA256 if available
    if [ -z "$SKIP_VERIFY" ] && [ -f "$TMP_DIR/${ARCHIVE_NAME}.sha256" ]; then
        log_info "Verifying SHA256 checksum..."
        cd "$TMP_DIR"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c "${ARCHIVE_NAME}.sha256" || {
                log_error "SHA256 verification failed"
                exit 1
            }
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c "${ARCHIVE_NAME}.sha256" || {
                log_error "SHA256 verification failed"
                exit 1
            }
        else
            log_warn "No SHA256 tool found, skipping verification"
        fi
        cd - >/dev/null
        log_success "Checksum verified"
    fi

    # Extract
    log_info "Extracting archive..."
    tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR" || {
        log_error "Failed to extract archive"
        exit 1
    }

    # Find extracted directory
    EXTRACTED_DIR=$(find "$TMP_DIR" -maxdepth 1 -type d -name "oxy-*" | head -1)
    if [ -z "$EXTRACTED_DIR" ]; then
        log_error "Could not find extracted directory"
        exit 1
    fi

    BINARY_PATH="$EXTRACTED_DIR/oxy"
    if [ ! -f "$BINARY_PATH" ]; then
        log_error "oxy binary not found in archive"
        exit 1
    fi
}

# Install binary and man page
install_files() {
    log_info "Installing oxy to $INSTALL_DIR..."

    # Create directories with proper permissions using install -d
    # -d = create directories
    # -m 755 = rwxr-xr-x (owner can write, others can read/execute)
    if [ -n "$SUDO" ]; then
        $SUDO install -dm755 "$INSTALL_DIR" 2>/dev/null || {
            # Fallback if install -d not available
            $SUDO mkdir -p "$INSTALL_DIR"
            $SUDO chmod 755 "$INSTALL_DIR"
        }
        $SUDO install -dm755 "$MAN_DIR" 2>/dev/null || {
            $SUDO mkdir -p "$MAN_DIR"
            $SUDO chmod 755 "$MAN_DIR"
        }
    else
        install -dm755 "$INSTALL_DIR" 2>/dev/null || mkdir -p "$INSTALL_DIR"
        install -dm755 "$MAN_DIR" 2>/dev/null || mkdir -p "$MAN_DIR"
    fi

    # Install binary
    # -m 755 = executable by all, writable by owner
    if [ -n "$SUDO" ]; then
        $SUDO install -m755 "$BINARY_PATH" "$INSTALL_DIR/oxy"
    else
        install -m755 "$BINARY_PATH" "$INSTALL_DIR/oxy"
    fi

    # Install man page if exists
    MAN_PAGE="$EXTRACTED_DIR/man/oxy.1"
    if [ -f "$MAN_PAGE" ]; then
        log_info "Installing man page..."
        if [ -n "$SUDO" ]; then
            $SUDO install -m644 "$MAN_PAGE" "$MAN_DIR/oxy.1"
        else
            install -m644 "$MAN_PAGE" "$MAN_DIR/oxy.1"
        fi
        log_success "Man page installed"
    fi

    log_success "oxy installed to $INSTALL_DIR/oxy"
}

# Verify installation
verify_install() {
    if command -v oxy >/dev/null 2>&1; then
        VERSION_INSTALLED=$(oxy --info 2>/dev/null | head -1 || echo "unknown")
        log_success "Installation verified: $VERSION_INSTALLED"
    else
        log_warn "oxy not in PATH. Add $INSTALL_DIR to your PATH:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

# Main
main() {
    echo "${CYAN}"
    echo "  ╦ ╦╔═╗╔╗ ╔═╗╦  ╦"
    echo "  ║║║║╣ ╠╩╗╚═╗║  ║"
    echo "  ╚╩╝╚═╝╚═╝╚═╝╩═╝╩═╝"
    echo "${NC}"
    echo "  ${DIM}Easy userspace bandwidth manager for Linux${NC}"
    echo

    check_root
    detect_arch
    get_latest_version
    download_release
    install_files
    verify_install

    echo
    log_success "Installation complete!"
    echo
    echo "  ${DIM}Quick start:${NC}"
    echo "    sudo oxy list              ${DIM}# List processes${NC}"
    echo "    sudo oxy strict -d 1mb wget ${DIM}# Limit download${NC}"
    echo "    sudo oxy --help            ${DIM}# Show all commands${NC}"
    echo
}

main "$@"
