#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

BIN=./agentic_credential_proxy_bin
MENUBAR_BIN=./acp_menubar_bin

# Build only when the binary is missing, or when asked to force one.
# `cargo clean` afterwards keeps ./target from lingering, which is also why a
# rebuild is always a cold one -- hence not doing it on every start.
if [ ! -x "$BIN" ] || [ "${1:-}" = "--rebuild" ]; then
    rm -f "$BIN"
    cargo build --release
    mv ./target/release/agentic-credential-proxy "$BIN"
    chmod 755 "$BIN"
    # Hardened runtime: macOS then ignores DYLD_INSERT_LIBRARIES and refuses
    # debugger attach, so nothing can run code inside the binary the keychain
    # trusts. Getting around it means a different binary, which prompts again.
    codesign --force -s - -o runtime "$BIN"
    cargo clean
fi

# Same rule for the menu bar app; it is one Swift file, so this takes seconds.
if [ ! -x "$MENUBAR_BIN" ] || [ "${1:-}" = "--rebuild" ]; then
    rm -f "$MENUBAR_BIN"
    swiftc -O menubar/ACPMenuBar.swift -o "$MENUBAR_BIN"
fi
[ "${1:-}" = "--rebuild" ] && shift

# The menu bar app lives and dies with the proxy, so restarts never stack icons.
"$MENUBAR_BIN" &
MENUBAR_PID=$!
trap 'kill "$MENUBAR_PID" 2>/dev/null || true' EXIT

"$BIN" --config ~/.config/agentic-credential-proxy/config.toml "$@"
# lsof -nP -iTCP -sTCP:LISTEN |grep agentic_credential_proxy_bin
