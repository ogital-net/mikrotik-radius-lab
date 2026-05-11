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
INGESTER_DIR="$SCRIPT_DIR/mikrotik-ingester"
DHCP_DIR="$SCRIPT_DIR/dhcp-server"
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
LAB="hotspot"
SWAP_LINES=0
DHCP_BACKEND="routeros"
FRESH=0

for arg in "$@"; do
    case "$arg" in
        arm64|arm|aarch64) GUEST_ARCH="arm64" ;;
        x64|x86_64|x86|amd64) GUEST_ARCH="x64" ;;
        --lab=hotspot)  LAB="hotspot" ;;
        --lab=dhcp)     LAB="dhcp" ;;
        --dhcp=routeros) DHCP_BACKEND="routeros" ;;
        --dhcp=external) DHCP_BACKEND="external" ;;
        --swap)         SWAP_LINES=1 ;;
        --fresh)        FRESH=1 ;;
        --stop|stop)    ACTION="stop" ;;
        --help|-h)      ACTION="help" ;;
        *) err "Unknown argument: $arg"; exit 1 ;;
    esac
done

VM_A_PORT=22221
VM_B_PORT=22223
if [ "$SWAP_LINES" = "1" ]; then
    VM_A_PORT=22223
    VM_B_PORT=22221
fi

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
    CHR_VERSION="7.21.4"
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
    CHR_VERSION="7.21.4"
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
    local name="${1:-mikrotik}"
    local vars_file="$IMAGES_DIR/efivars-${name}-arm64.fd"
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

prepare_chr_overlay() {
    local name="$1"
    local overlay="$IMAGES_DIR/chr-${name}-overlay.qcow2"
    if [ ! -f "$overlay" ]; then
        qemu-img create -f qcow2 -F raw -b "$CHR_IMG" "$overlay" >/dev/null
    fi
    echo "$overlay"
}

wipe_chr_overlays() {
    local removed=0
    for f in "$IMAGES_DIR"/chr-*-overlay.qcow2 "$IMAGES_DIR"/efivars-*.fd; do
        [ -f "$f" ] || continue
        rm -f "$f"
        removed=$((removed + 1))
    done
    if [ "$removed" -gt 0 ]; then
        log "Wiped $removed CHR overlay file(s) for fresh boot"
    else
        info "No CHR overlays to wipe"
    fi
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

build_ingester() {
    log "Building Mikrotik ingester..."
    (cd "$INGESTER_DIR" && cargo build --release 2>&1 | tail -5)
    log "Ingester built"
}

build_dhcp_server() {
    log "Building dhcp-server..."
    (cd "$DHCP_DIR" && cargo build --release 2>&1 | tail -5)
    log "dhcp-server built"
}

start_clickhouse() {
    log "Starting ClickHouse via docker compose..."
    (cd "$INGESTER_DIR" && docker compose up -d) >/dev/null 2>&1 || {
        err "docker compose up failed (is Docker running?)"
        exit 1
    }
    for _ in $(seq 1 30); do
        if curl -sf -u ingester:ingester 'http://localhost:8123/ping' >/dev/null 2>&1; then
            log "ClickHouse ready (http://localhost:8123/play)"
            return
        fi
        sleep 1
    done
    err "ClickHouse did not become ready"
    exit 1
}

start_ingester() {
    mkdir -p "$PID_DIR"
    log "Starting Mikrotik ingester on 0.0.0.0:5140..."

    RUST_LOG=info "$INGESTER_DIR/target/release/mikrotik-ingester" \
        > "$PID_DIR/ingester.log" 2>&1 &
    echo $! > "$PID_DIR/ingester.pid"

    sleep 1
    if kill -0 "$(cat "$PID_DIR/ingester.pid")" 2>/dev/null; then
        log "Ingester running (PID $(cat "$PID_DIR/ingester.pid"))"
    else
        err "Ingester failed to start; see $PID_DIR/ingester.log"
        exit 1
    fi
}

# ─── Start RADIUS ──────────────────────────────────────────────

start_dhcp_server() {
    mkdir -p "$PID_DIR"
    log "Starting dhcp-server (external DHCP backend)..."
    log "Waiting a moment for CHR-CORE :22229 listener to be ready..."
    for _ in $(seq 1 30); do
        if nc -z 127.0.0.1 22229 2>/dev/null; then
            break
        fi
        sleep 1
    done

    RUST_LOG=info "$DHCP_DIR/target/release/dhcp-server" \
        --qemu 127.0.0.1:22229 \
        --radius 127.0.0.1:1812 \
        --radius-secret secret \
        > "$PID_DIR/dhcp-server.log" 2>&1 &
    echo $! > "$PID_DIR/dhcp-server.pid"

    sleep 1
    if kill -0 "$(cat "$PID_DIR/dhcp-server.pid")" 2>/dev/null; then
        log "dhcp-server running (PID $(cat "$PID_DIR/dhcp-server.pid"))"
    else
        err "dhcp-server failed to start; see $PID_DIR/dhcp-server.log"
        exit 1
    fi
}

start_radius() {
    mkdir -p "$PID_DIR"
    log "Starting RADIUS server on 0.0.0.0:1812..."

    RUST_LOG=info "$RADIUS_DIR/target/release/radius-server" \
        > "$PID_DIR/radius.log" 2>&1 &
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

start_chr_access() {
    mkdir -p "$PID_DIR"
    log "Starting CHR-ACCESS (${GUEST_ARCH})..."
    local overlay
    overlay="$(prepare_chr_overlay access)"

    if [ "$GUEST_ARCH" = "arm64" ]; then
        local efi_code efi_vars
        efi_code="$(find_efi_code)"
        efi_vars="$(prepare_efi_vars access)"

        $CHR_QEMU_BIN \
            -name chr-access \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive if=pflash,format=raw,readonly=on,unit=0,file="$efi_code" \
            -drive if=pflash,format=raw,unit=1,file="$efi_vars" \
            -drive file="$overlay",format=qcow2,if=none,id=disk0 \
            -device nvme,drive=disk0,serial=access \
            -netdev socket,id=up,listen=:22228 \
            -device virtio-net-pci,netdev=up,mac=52:54:00:00:aa:01 \
            -netdev socket,id=lineA,listen=:22221 \
            -device virtio-net-pci,netdev=lineA,mac=52:54:00:00:aa:02 \
            -netdev socket,id=lineB,listen=:22223 \
            -device virtio-net-pci,netdev=lineB,mac=52:54:00:00:aa:03 \
            -netdev user,id=wan,hostfwd=tcp::2223-:22 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:aa:00 \
            -vga none \
            -serial tcp::4445,server,nowait \
            -display none \
            &
    else
        $CHR_QEMU_BIN \
            -name chr-access \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive file="$overlay",format=qcow2,if=virtio \
            -netdev socket,id=up,listen=:22228 \
            -device virtio-net-pci,netdev=up,mac=52:54:00:00:aa:01 \
            -netdev socket,id=lineA,listen=:22221 \
            -device virtio-net-pci,netdev=lineA,mac=52:54:00:00:aa:02 \
            -netdev socket,id=lineB,listen=:22223 \
            -device virtio-net-pci,netdev=lineB,mac=52:54:00:00:aa:03 \
            -netdev user,id=wan,hostfwd=tcp::2223-:22 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:aa:00 \
            -serial tcp::4445,server,nowait \
            -display none \
            &
    fi

    echo $! > "$PID_DIR/chr-access.pid"
    log "CHR-ACCESS running (PID $(cat "$PID_DIR/chr-access.pid"))"
}

start_chr_core() {
    mkdir -p "$PID_DIR"
    log "Starting CHR-CORE (${GUEST_ARCH})..."
    local overlay
    overlay="$(prepare_chr_overlay core)"

    local server_nic_args=()
    if [ "$DHCP_BACKEND" = "external" ]; then
        server_nic_args=(
            -netdev socket,id=server,listen=:22229
            -device virtio-net-pci,netdev=server,mac=52:54:00:00:c0:03
        )
    fi

    if [ "$GUEST_ARCH" = "arm64" ]; then
        local efi_code efi_vars
        efi_code="$(find_efi_code)"
        efi_vars="$(prepare_efi_vars core)"

        $CHR_QEMU_BIN \
            -name chr-core \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive if=pflash,format=raw,readonly=on,unit=0,file="$efi_code" \
            -drive if=pflash,format=raw,unit=1,file="$efi_vars" \
            -drive file="$overlay",format=qcow2,if=none,id=disk0 \
            -device nvme,drive=disk0,serial=core \
            -netdev socket,id=down,connect=127.0.0.1:22228 \
            -device virtio-net-pci,netdev=down,mac=52:54:00:00:c0:01 \
            -netdev user,id=wan,hostfwd=tcp::2222-:22,hostfwd=tcp::8291-:8291 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:c0:02 \
            "${server_nic_args[@]}" \
            -vga none \
            -serial tcp::4444,server,nowait \
            -display none \
            &
    else
        $CHR_QEMU_BIN \
            -name chr-core \
            -machine "$CHR_MACHINE" $CHR_ACCEL \
            $CHR_CPU \
            -smp "$CHR_SMP" \
            -m "$CHR_MEM" \
            -drive file="$overlay",format=qcow2,if=virtio \
            -netdev socket,id=down,connect=127.0.0.1:22228 \
            -device virtio-net-pci,netdev=down,mac=52:54:00:00:c0:01 \
            -netdev user,id=wan,hostfwd=tcp::2222-:22,hostfwd=tcp::8291-:8291 \
            -device virtio-net-pci,netdev=wan,mac=52:54:00:00:c0:02 \
            "${server_nic_args[@]}" \
            -serial tcp::4444,server,nowait \
            -display none \
            &
    fi

    echo $! > "$PID_DIR/chr-core.pid"
    log "CHR-CORE running (PID $(cat "$PID_DIR/chr-core.pid"))"
}

start_vm_a() {
    mkdir -p "$PID_DIR"
    log "Starting VM-A (Lubuntu, → :$VM_A_PORT)..."
    $CLIENT_QEMU_BIN \
        -name vm-a \
        -machine q35 $CLIENT_ACCEL \
        $CLIENT_CPU \
        -smp 2 \
        -m 2048 \
        -cdrom "$IMAGES_DIR/client-x86_64.iso" \
        -netdev socket,id=net0,connect=127.0.0.1:$VM_A_PORT \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:00:0a:01 \
        -vga virtio \
        -display cocoa \
        &
    echo $! > "$PID_DIR/vm-a.pid"
    log "VM-A running (PID $(cat "$PID_DIR/vm-a.pid"))"
}

start_vm_b() {
    mkdir -p "$PID_DIR"
    log "Starting VM-B (Lubuntu, → :$VM_B_PORT)..."
    $CLIENT_QEMU_BIN \
        -name vm-b \
        -machine q35 $CLIENT_ACCEL \
        $CLIENT_CPU \
        -smp 2 \
        -m 2048 \
        -cdrom "$IMAGES_DIR/client-x86_64.iso" \
        -netdev socket,id=net0,connect=127.0.0.1:$VM_B_PORT \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:00:0b:01 \
        -vga virtio \
        -display cocoa \
        &
    echo $! > "$PID_DIR/vm-b.pid"
    log "VM-B running (PID $(cat "$PID_DIR/vm-b.pid"))"
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

# ─── Configure Mikrotik via serial (expect) ───────────────────

write_chr_expect_script() {
    local expect_script="$1"
    cat > "$expect_script" << 'EXPECT_SCRIPT'
set timeout 60
set serial_port [lindex $argv 0]
set config_file [lindex $argv 1]

log_user 1

# Match the RouterOS prompt: "[admin@MikroTik] > " or similar
# Use a loose pattern to handle ANSI escape codes on serial
set prompt {> $}

spawn socat - tcp:localhost:$serial_port,connect-timeout=120

# Wait for socat connection to establish
sleep 2

# Send a few enters to trigger the login prompt, then drain any initial output.
# RouterOS often resets the console on first connect — we need to wait for it
# to settle before attempting login.
send "\r"
sleep 3

# Drain: consume everything buffered so far (the first login prompt that gets reset)
expect *

# Now send enter to get the real, stable login prompt
send "\r"

# Procedure to log in: tries empty password first (first boot), then "admin"
proc do_login {} {
    global prompt

    expect {
        -re {[Ll]ogin:} {}
        -re $prompt { return }
        timeout {
            puts "timeout waiting for login prompt"
            exit 1
        }
    }

    send "admin\r"

    expect {
        -re {[Pp]assword:} {
            # Try empty password first (first boot)
            send "\r"
        }
        -re $prompt { return }
        timeout {
            puts "timeout waiting for password prompt"
            exit 1
        }
    }

    # Check what happens after password
    expect {
        -re {[Ll]ogin failed|incorrect} {
            # Empty password failed — router already configured, password is "admin"
            # Wait for the console to reset and show login again
            expect -re {[Ll]ogin:}
            send "admin\r"
            expect -re {[Pp]assword:}
            send "admin\r"
        }
        -re {new password|[Cc]hange.*[Pp]assword} {
            # First boot — set password to "admin"
            send "admin\r"
            expect -re {repeat|again|confirm|new password}
            send "admin\r"
        }
        -re {agreement|license|\[Y\]} {
            send "Y\r"
            expect -re $prompt
            return
        }
        -re $prompt { return }
    }

    # Handle license agreement or prompt after password change / successful login
    expect {
        -re {agreement|license|\[Y\]} {
            send "Y\r"
            expect -re $prompt
        }
        -re $prompt {}
        timeout {
            send "\r"
            expect -re $prompt
        }
    }
}

do_login

# Read config file and send each command
set fp [open $config_file r]
while {[gets $fp line] >= 0} {
    set line [string trim $line]
    if {$line eq "" || [string index $line 0] eq "#"} continue
    send "$line\r"
    expect {
        -re $prompt {}
        -re {expected end of command|invalid command|bad command|failure:|no such item|syntax error} {
            puts "WARNING: command may have failed: $line"
            expect -re $prompt
        }
        timeout {
            puts "timeout after: $line"
            # Try to recover by sending enter
            send "\r"
            expect -re $prompt
        }
    }
}
close $fp

send "\r"
expect -re $prompt

puts "\nconfiguration applied successfully"
close
EXPECT_SCRIPT
}

apply_chr_config() {
    local serial_port="$1"
    local config_file="$2"
    local label="${3:-$(basename "$config_file")}"
    local expect_script
    expect_script="$(mktemp /tmp/mikrotik-config.XXXXXX.exp)"
    write_chr_expect_script "$expect_script"
    expect "$expect_script" "$serial_port" "$config_file"
    local rc=$?
    rm -f "$expect_script"
    if [ $rc -eq 0 ]; then
        log "Applied $label on serial :$serial_port"
    else
        warn "Auto-config may have failed for $label (serial :$serial_port, rc=$rc)"
        info "Connect manually: socat -,rawer tcp:localhost:$serial_port"
        info "Then paste commands from: $config_file"
    fi
    return $rc
}

configure_mikrotik() {
    local boot_wait="${MIKROTIK_BOOT_WAIT:-$CHR_BOOT_DEFAULT}"
    log "Waiting ${boot_wait}s for RouterOS to boot..."
    sleep "$boot_wait"
    log "Configuring RouterOS via serial (expect)..."
    apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-hotspot.rsc" "hotspot"
    apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-logging.rsc" "logging"
    apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-traffic-flow.rsc" "traffic-flow"
}

configure_dhcp_lab() {
    local boot_wait="${MIKROTIK_BOOT_WAIT:-$CHR_BOOT_DEFAULT}"
    log "Waiting ${boot_wait}s for both CHRs to boot..."
    sleep "$boot_wait"
    log "Configuring CHR-ACCESS (serial :4445)..."
    if [ "$DHCP_BACKEND" = "external" ]; then
        apply_chr_config 4445 "$CONFIGS_DIR/mikrotik-access-relay.rsc" "access (per-port relays)"
    else
        apply_chr_config 4445 "$CONFIGS_DIR/mikrotik-access.rsc" "access"
    fi
    log "Configuring CHR-CORE (serial :4444)..."
    if [ "$DHCP_BACKEND" = "external" ]; then
        apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-core-relay.rsc" "core (router only)"
    else
        apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-core.rsc" "core"
    fi
    apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-logging.rsc" "logging"
    apply_chr_config 4444 "$CONFIGS_DIR/mikrotik-traffic-flow.rsc" "traffic-flow"
}

# ─── Upload custom HotSpot HTML to Mikrotik via SCP ──────────

upload_hotspot_html() {
    log "Uploading custom hotspot HTML pages to Mikrotik (SCP)..."

    local expect_script
    expect_script="$(mktemp /tmp/mikrotik-scp.XXXXXX.exp)"

    cat > "$expect_script" << 'SCP_SCRIPT'
set timeout 20
set src [lindex $argv 0]
set dst [lindex $argv 1]

spawn scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -P 2222 $src admin@localhost:$dst

expect {
    -re {[Pp]assword:} {
        send "admin\r"
        exp_continue
    }
    "100%" {
        exit 0
    }
    eof {
        exit 0
    }
    timeout {
        exit 1
    }
}
SCP_SCRIPT

    local retries=10
    local uploaded=0

    # Wait for SSH to be reachable
    for i in $(seq 1 $retries); do
        if expect "$expect_script" /dev/null /dev/null 2>/dev/null; then
            break
        fi
        sleep 3
    done

    for html_file in "$CONFIGS_DIR"/hotspot-html/*.html; do
        [ -f "$html_file" ] || continue
        local fname
        fname="$(basename "$html_file")"

        if expect "$expect_script" "$html_file" "/hotspot/$fname"; then
            info "  uploaded $fname"
            uploaded=$((uploaded + 1))
        else
            warn "  failed to upload $fname"
        fi
    done

    rm -f "$expect_script"

    if [ "$uploaded" -gt 0 ]; then
        log "Uploaded $uploaded hotspot HTML file(s)"
    else
        warn "Could not upload HTML files"
        info "Upload manually: scp -P 2222 configs/hotspot-html/*.html admin@localhost:/hotspot/"
    fi
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

  Usage: ./run.sh [arm64|x64] [--lab=hotspot|dhcp] [OPTIONS]

  On Apple Silicon, defaults to ARM64 CHR (native).
  On x86_64 hosts, defaults to x86_64 CHR (native).
  Use "x64" to force x86_64 emulation on any host.

  Options:
    arm64           Use ARM64 CHR (TCG, NVMe disk)
    x64             Use x86_64 CHR (HVF on x86, TCG on ARM)
    --lab=hotspot   HotSpot lab (default): one CHR + one Lubuntu, captive portal
    --lab=dhcp      Option 82 lab: CHR-ACCESS + CHR-CORE + two Lubuntus,
                    DHCP-driven RADIUS subscriber identification
    --dhcp=routeros (dhcp lab, default) CHR-CORE runs RouterOS' built-in
                    DHCP server with use-radius=yes — models a small ISP
                    where one Mikrotik does everything.
    --dhcp=external (dhcp lab) CHR-CORE acts as a DHCP relay; an external
                    dhcp-server (Rust, on the host) hands out leases —
                    models a large ISP / enterprise where DHCP is a
                    separate box (Kea, ISC, Windows DHCP).
    --swap          (dhcp lab) Swap VM-A and VM-B socket ports — VM-A
                    on line B (:22223) and VM-B on line A (:22221).
                    Used to verify policy follows the wire (T3).
    --fresh         Wipe CHR overlay disks before boot so every CHR comes
                    up with a clean RouterOS. Use whenever you switch
                    between --lab=hotspot and --lab=dhcp, or between
                    --dhcp=routeros and --dhcp=external — leftover config
                    from the previous mode otherwise contaminates the run.
    --stop          Stop all running components
    --help          Show this help

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
    info "lab=$LAB dhcp=$DHCP_BACKEND"
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
    if [ "$FRESH" = "1" ]; then
        wipe_chr_overlays
    fi
    build_radius
    build_ingester
    if [ "$LAB" = "dhcp" ] && [ "$DHCP_BACKEND" = "external" ]; then
        build_dhcp_server
    fi

    echo ""
    log "Setup complete. Starting lab..."
    echo ""

    trap cleanup EXIT INT TERM

    case "$LAB" in
        hotspot) main_hotspot ;;
        dhcp)    main_dhcp ;;
        *) err "Unknown LAB=$LAB"; exit 1 ;;
    esac
}

main_hotspot() {
    start_clickhouse
    start_ingester
    start_radius
    start_mikrotik
    configure_mikrotik
    upload_hotspot_html
    start_client

    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │  Lab is running!                            │"
    echo "  │                                             │"
    echo "  │  Captive portal:  admin / p@ssw0rd          │"
    echo "  │  Mikrotik SSH:    ssh -p 2222 admin@localhost│"
    echo "  │  Mikrotik pass:   admin                     │"
    echo "  │  Mikrotik serial: nc localhost 4444         │"
    echo "  │  ClickHouse UI:   http://localhost:8123/play │"
    echo "  │  Lubuntu: 'Try Lubuntu' -> open Firefox     │"
    echo "  │                                             │"
    echo "  │  Press Ctrl+C to stop everything            │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""

    wait "$(cat "$PID_DIR/client.pid")" 2>/dev/null || true
}

main_dhcp() {
    start_clickhouse
    start_ingester
    start_radius

    start_chr_access
    sleep 2
    start_chr_core
    if [ "$DHCP_BACKEND" = "external" ]; then
        start_dhcp_server
    fi
    start_vm_a
    start_vm_b

    configure_dhcp_lab

    echo ""
    echo "  ┌────────────────────────────────────────────────┐"
    echo "  │  DHCP / Option 82 lab is running!              │"
    echo "  │                                                │"
    echo "  │  CHR-CORE   SSH:    ssh -p 2222 admin@localhost│"
    echo "  │  CHR-ACCESS SSH:    ssh -p 2223 admin@localhost│"
    echo "  │  CHR-CORE   serial: nc localhost 4444          │"
    echo "  │  CHR-ACCESS serial: nc localhost 4445          │"
    echo "  │  ClickHouse UI:     http://localhost:8123/play │"
    echo "  │  RADIUS log:        watch radius-server stdout │"
    echo "  │                                                │"
    if [ "$SWAP_LINES" = "1" ]; then
        echo "  │  --swap ACTIVE: VM-A on :22223, VM-B on :22221 │"
        echo "  │  T3: policies should follow the wire, not VMs. │"
    else
        echo "  │  VM-A on line A (ether2 → 192.168.50.10)       │"
        echo "  │  VM-B on line B (ether3 → pool 100-200)        │"
        echo "  │                                                │"
        echo "  │  T3 swap test: ./run.sh --stop, then            │"
        echo "  │  ./run.sh --lab=dhcp --swap                    │"
    fi
    echo "  │                                                │"
    echo "  │  Press Ctrl+C to stop everything               │"
    echo "  └────────────────────────────────────────────────┘"
    echo ""

    wait "$(cat "$PID_DIR/vm-a.pid")" 2>/dev/null || true
}

case "$ACTION" in
    run)  main ;;
    stop) do_stop ;;
    help) show_help ;;
esac
