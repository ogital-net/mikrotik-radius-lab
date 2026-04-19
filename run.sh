#!/usr/bin/env bash
set -euo pipefail

#
# Captive Portal Lab
# Mikrotik CHR + RADIUS (radius-rs) + Lubuntu Client
#
# Usage: ./run.sh [arm64|x64] [--stop|--help]
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/images"
CONFIGS_DIR="$SCRIPT_DIR/configs"
RADIUS_DIR="$SCRIPT_DIR/radius-server"
PID_DIR="$SCRIPT_DIR/.run"

HOST_ARCH="$(uname -m)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*" >&2; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

# ─── Parse arguments ────────────────────────────────────────────

ACTION="run"
GUEST_ARCH="auto"

for arg in "$@"; do
    case "$arg" in
        arm64|arm|aarch64) GUEST_ARCH="arm64" ;;
        x64|x86_64|x86|amd64) GUEST_ARCH="x64" ;;
        --stop|stop)    ACTION="stop" ;;
        --help|-h)      ACTION="help" ;;
        *) err "Unknown argument: $arg"; exit 1 ;;
    esac
done

# Auto-detect: use native architecture for CHR
if [ "$GUEST_ARCH" = "auto" ]; then
    if [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        GUEST_ARCH="arm64"
    else
        GUEST_ARCH="x64"
    fi
fi

# ─── CHR VM config ─────────────────────────────────────────────

if [ "$GUEST_ARCH" = "arm64" ]; then
    CHR_VERSION="7.20.8"
    CHR_QEMU_BIN="qemu-system-aarch64"
    CHR_IMG="$IMAGES_DIR/chr-${CHR_VERSION}-arm64.img"
    CHR_IMG_NAME="chr-${CHR_VERSION}-arm64.img"
    CHR_URL="https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}-arm64.img.zip"
    # TCG required — HVF causes kernel panic on ARM64 CHR
    CHR_ACCEL="-accel tcg"
    CHR_CPU="-cpu cortex-a710"
    CHR_MACHINE="virt"
    CHR_SMP=2
    CHR_MEM=1024
    CHR_BOOT_DEFAULT=45
else
    CHR_VERSION="7.20.8"
    CHR_QEMU_BIN="qemu-system-x86_64"
    CHR_IMG="$IMAGES_DIR/chr-x86_64.img"
    CHR_IMG_NAME="chr-${CHR_VERSION}.img"
    CHR_URL="https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip"
    CHR_MACHINE="q35"
    CHR_SMP=1
    CHR_MEM=256
    CHR_BOOT_DEFAULT=60
    if [ "$HOST_ARCH" = "x86_64" ]; then
        CHR_ACCEL="-accel hvf"
        CHR_CPU="-cpu host"
    else
        CHR_ACCEL="-accel tcg,thread=multi"
        CHR_CPU="-cpu qemu64"
    fi
fi

# ─── Client VM config (always x86_64) ────────��─────────────────

CLIENT_QEMU_BIN="qemu-system-x86_64"
CLIENT_URL="https://cdimage.ubuntu.com/lubuntu/releases/24.04/release/lubuntu-24.04.4-desktop-amd64.iso"

if [ "$HOST_ARCH" = "x86_64" ]; then
    CLIENT_ACCEL="-accel hvf"
    CLIENT_CPU="-cpu host"
else
    CLIENT_ACCEL="-accel tcg,thread=multi"
    CLIENT_CPU="-cpu qemu64"
fi

# ─── UEFI firmware helpers (ARM64) ─────────────────────────────

find_efi_code() {
    for p in \
        /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
        /usr/local/share/qemu/edk2-aarch64-code.fd \
        /usr/share/AAVMF/AAVMF_CODE.fd \
        /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
        if [ -f "$p" ]; then echo "$p"; return; fi
    done
}

find_efi_vars_template() {
    for v in \
        /opt/homebrew/share/qemu/edk2-arm-vars.fd \
        /usr/local/share/qemu/edk2-arm-vars.fd \
        /usr/share/AAVMF/AAVMF_VARS.fd \
        /usr/share/qemu-efi-aarch64/QEMU_VARS.fd; do
        if [ -f "$v" ]; then echo "$v"; return; fi
    done
}

prepare_efi_vars() {
    local vars_file="$IMAGES_DIR/efivars-mikrotik-arm64.fd"
    if [ ! -f "$vars_file" ]; then
        local efi_code efi_vars_src code_size
        efi_code="$(find_efi_code)"
        efi_vars_src="$(find_efi_vars_template)"
        if [ -n "$efi_vars_src" ]; then
            cp "$efi_vars_src" "$vars_file"
        else
            touch "$vars_file"
        fi
        # Pad to match code ROM size (both pflash units must be identical size)
        code_size=$(stat -f%z "$efi_code" 2>/dev/null || stat -Lc%s "$efi_code")
        dd if=/dev/zero of="$vars_file" bs=1 count=0 seek="$code_size" 2>/dev/null
    fi
    echo "$vars_file"
}

# ─── Dependency check ───────────────────────────────────────────

check_deps() {
    local missing=()

    command -v "$CHR_QEMU_BIN" &>/dev/null   || missing+=("$CHR_QEMU_BIN")
    command -v "$CLIENT_QEMU_BIN" &>/dev/null || missing+=("$CLIENT_QEMU_BIN")
    command -v qemu-img &>/dev/null           || missing+=("qemu-img")
    command -v socat &>/dev/null              || missing+=("socat")
    command -v cargo &>/dev/null              || missing+=("cargo (rustup)")
    command -v curl &>/dev/null               || missing+=("curl")
    command -v unzip &>/dev/null              || missing+=("unzip")

    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing dependencies:"
        for dep in "${missing[@]}"; do
            echo "  - $dep"
        done
        echo ""
        echo "Install: brew install qemu socat && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi

    if [ "$GUEST_ARCH" = "arm64" ]; then
        local efi_code
        efi_code="$(find_efi_code)"
        if [ -z "$efi_code" ]; then
            err "No UEFI firmware found for aarch64."
            echo "Install: brew install qemu"
            exit 1
        fi
    fi

    log "Dependencies OK"
}

# ─── Download images ────────────────────────────────────────────

download_images() {
    mkdir -p "$IMAGES_DIR"

    # Mikrotik CHR
    if [ ! -f "$CHR_IMG" ]; then
        log "Downloading Mikrotik CHR ${CHR_VERSION} (${GUEST_ARCH})..."
        local zip="$IMAGES_DIR/chr.img.zip"
        curl -L --progress-bar -o "$zip" "$CHR_URL"

        log "Extracting..."
        unzip -o "$zip" -d "$IMAGES_DIR"
        # Rename if extracted name differs from target
        if [ "$IMAGES_DIR/$CHR_IMG_NAME" != "$CHR_IMG" ]; then
            mv "$IMAGES_DIR/$CHR_IMG_NAME" "$CHR_IMG"
        fi

        rm -f "$zip"
        log "CHR image ready"
    else
        log "CHR image exists"
    fi

    # Lubuntu Desktop x64 (LXQt - much lighter than Ubuntu GNOME)
    if [ ! -f "$IMAGES_DIR/client-x86_64.iso" ]; then
        log "Downloading Lubuntu 24.04 Desktop (x64) ~3.2GB..."
        curl -L --progress-bar -o "$IMAGES_DIR/client-x86_64.iso" "$CLIENT_URL"
        log "Client ISO ready"
    else
        log "Client ISO exists"
    fi
}

# ─��─ Build RADIUS server ───────────────────────────────────────

build_radius() {
    log "Building RADIUS server..."
    (cd "$RADIUS_DIR" && cargo build --release 2>&1 | tail -5)
    log "RADIUS server built"
}

# ─── Start RADIUS ──────────────────────────────────────────────

start_radius() {
    mkdir -p "$PID_DIR"
    log "Starting RADIUS server on 0.0.0.0:1812..."

    RUST_LOG=info "$RADIUS_DIR/target/release/radius-server" &
    echo $! > "$PID_DIR/radius.pid"

    sleep 1
    if kill -0 "$(cat "$PID_DIR/radius.pid")" 2>/dev/null; then
        log "RADIUS server running (PID $(cat "$PID_DIR/radius.pid"))"
    else
        err "RADIUS server failed to start"
        exit 1
    fi
}

# ─── Start Mikrotik VM ─────────────────────────────────────────

start_mikrotik() {
    mkdir -p "$PID_DIR"
    log "Starting Mikrotik CHR VM (${GUEST_ARCH})..."

    if [ "$GUEST_ARCH" = "arm64" ]; then
        local efi_code efi_vars
        efi_code="$(find_efi_code)"
        efi_vars="$(prepare_efi_vars)"

        $CHR_QEMU_BIN \
            -name mikrotik-chr \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive if=pflash,format=raw,readonly=on,unit=0,file="$efi_code" \
            -drive if=pflash,format=raw,unit=1,file="$efi_vars" \
            -drive file="$CHR_IMG",format=raw,if=none,id=disk0 \
            -device nvme,drive=disk0,serial=chr \
            -netdev user,id=wan,hostfwd=tcp::2222-:22,hostfwd=tcp::8291-:8291 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:01:01 \
            -netdev socket,id=lan,listen=:22222 \
            -device virtio-net-pci,netdev=lan,mac=52:54:00:00:01:02 \
            -vga none \
            -serial tcp::4444,server,nowait \
            -display none \
            &
    else
        $CHR_QEMU_BIN \
            -name mikrotik-chr \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive file="$CHR_IMG",format=raw,if=virtio \
            -netdev user,id=wan,hostfwd=tcp::2222-:22,hostfwd=tcp::8291-:8291 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:01:01 \
            -netdev socket,id=lan,listen=:22222 \
            -device virtio-net-pci,netdev=lan,mac=52:54:00:00:01:02 \
            -serial tcp::4444,server,nowait \
            -display none \
            &
    fi

    echo $! > "$PID_DIR/mikrotik.pid"
    log "Mikrotik VM running (PID $(cat "$PID_DIR/mikrotik.pid"))"
}

# ─── Start Client VM ───────────────────────────────────────────

start_client() {
    mkdir -p "$PID_DIR"
    log "Starting Client VM (Lubuntu LXQt + Firefox)..."
    info "Select 'Try Lubuntu' for live session"

    $CLIENT_QEMU_BIN \
        -name client-vm \
        -machine q35 $CLIENT_ACCEL \
        $CLIENT_CPU \
        -smp 2 \
        -m 2048 \
        -cdrom "$IMAGES_DIR/client-x86_64.iso" \
        -netdev socket,id=net0,connect=127.0.0.1:22222 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:00:02:01 \
        -vga virtio \
        -display cocoa \
        &

    echo $! > "$PID_DIR/client.pid"
    log "Client VM running (PID $(cat "$PID_DIR/client.pid"))"
}

# ─── Configure Mikrotik via serial ──────────────────────────────

configure_mikrotik() {
    local boot_wait="${MIKROTIK_BOOT_WAIT:-$CHR_BOOT_DEFAULT}"
    log "Waiting ${boot_wait}s for RouterOS to boot..."
    sleep "$boot_wait"

    log "Sending configuration via serial (port 4444)..."

    {
        sleep 2
        # Login sequence: admin, empty password, set new password
        # Note: some versions show a license prompt (Enter skips it)
        printf "\r\n"
        sleep 3
        printf "admin\r\n"
        sleep 2
        # Empty password (current default)
        printf "\r\n"
        sleep 3
        # Enter skips license prompt if present, harmless otherwise
        printf "\r\n"
        sleep 3
        # New password prompt (required on fresh RouterOS 7.x)
        printf "admin\r\n"
        sleep 2
        # Repeat new password
        printf "admin\r\n"
        sleep 5

        # Send config commands
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            printf "%s\r\n" "$line"
            sleep 2
        done < "$CONFIGS_DIR/mikrotik-hotspot.rsc"

        sleep 2
    } | socat - tcp:localhost:4444,connect-timeout=120 > /dev/null 2>&1 || true

    log "Configuration sent"
    warn "If auto-config failed, connect manually:"
    info "  socat -,rawer tcp:localhost:4444"
    info "  Then paste commands from: configs/mikrotik-hotspot.rsc"
}

# ─── Stop all ───────────────────────────────────────────────────

do_stop() {
    log "Stopping all components..."

    if [ -d "$PID_DIR" ]; then
        for pidfile in "$PID_DIR"/*.pid; do
            [ -f "$pidfile" ] || continue
            local pid name
            pid=$(cat "$pidfile")
            name=$(basename "$pidfile" .pid)
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                log "Stopped $name (PID $pid)"
            fi
            rm -f "$pidfile"
        done
        rmdir "$PID_DIR" 2>/dev/null || true
    fi

    log "Done"
}

cleanup() {
    echo ""
    do_stop
}

# ─── Help ───────────────────────────────────────────────────────

show_help() {
    cat << 'EOF'

  Captive Portal Lab
  ==================

  Usage: ./run.sh [arm64|x64] [OPTIONS]

  On Apple Silicon, defaults to ARM64 CHR (native).
  On x86_64 hosts, defaults to x86_64 CHR (native).
  Use "x64" to force x86_64 emulation on any host.

  Options:
    arm64    Use ARM64 CHR (TCG, NVMe disk)
    x64      Use x86_64 CHR (HVF on x86, TCG on ARM)
    --stop   Stop all running components
    --help   Show this help

  Components:
    Mikrotik CHR    Router with HotSpot captive portal
    RADIUS Server   Rust-based auth server (radius-rs)
    Lubuntu Client  Live ISO with LXQt + Firefox (lightweight)

  Credentials:
    Captive Portal   admin / p@ssw0rd
    Mikrotik SSH     ssh -p 2222 admin@localhost (password: admin)

  Network topology:
    Client (192.168.88.x) --> Mikrotik ether2 (192.168.88.1)
    Mikrotik ether1 (DHCP) --> QEMU NAT --> Host --> Internet
    Mikrotik --> RADIUS @ host:1812 (via 10.0.2.2)

  Notes:
    ARM64 CHR uses TCG emulation (HVF causes kernel panic).
    Same-arch TCG is still faster than cross-arch x86 emulation.
    Client VM is always x86_64 Lubuntu.

  Environment variables:
    MIKROTIK_BOOT_WAIT   Seconds to wait for RouterOS boot
                         (default: 30 for arm64, 60 for x64)

EOF
}

# ─── Main ───────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${CYAN}  ╔═══════════════════════════════════════╗${NC}"
    if [ "$GUEST_ARCH" = "arm64" ]; then
        echo -e "${CYAN}  ║     Captive Portal Lab (arm64)        ║${NC}"
    else
        echo -e "${CYAN}  ║       Captive Portal Lab (x64)        ║${NC}"
    fi
    echo -e "${CYAN}  ╚═══════════════════════════════════════╝${NC}"
    echo ""

    if [ "$GUEST_ARCH" = "arm64" ]; then
        info "ARM64 CHR with TCG emulation (NVMe disk)"
        echo ""
    elif [ "$HOST_ARCH" != "x86_64" ]; then
        warn "Running x64 emulation on ${HOST_ARCH} (TCG multi-thread)"
        warn "Performance will be slower than native"
        echo ""
    fi

    check_deps
    download_images
    build_radius

    echo ""
    log "Setup complete. Starting lab..."
    echo ""

    trap cleanup EXIT INT TERM

    start_radius
    start_mikrotik
    configure_mikrotik
    start_client

    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │  Lab is running!                            │"
    echo "  │                                             │"
    echo "  │  Captive portal:  admin / p@ssw0rd          │"
    echo "  │  Mikrotik SSH:    ssh -p 2222 admin@localhost│"
    echo "  │  Mikrotik pass:   admin                     │"
    echo "  │  Mikrotik serial: nc localhost 4444         │"
    echo "  │  Lubuntu: 'Try Lubuntu' -> open Firefox     │"
    echo "  │                                             │"
    echo "  │  Press Ctrl+C to stop everything            │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""

    # Wait for client VM to exit
    wait "$(cat "$PID_DIR/client.pid")" 2>/dev/null || true
}

case "$ACTION" in
    run)  main ;;
    stop) do_stop ;;
    help) show_help ;;
esac
