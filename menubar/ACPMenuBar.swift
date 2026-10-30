// Menu bar companion for agentic-credential-proxy: per-target counters, and a
// switch to pause and resume forwarding, for every running instance.
//
//   swiftc -O menubar/ACPMenuBar.swift -o acp_menubar_bin && ./acp_menubar_bin &
//
// It holds no credentials and opens no network port. Everything goes through
// the proxies' control sockets, which only answer processes running as the same
// user and only understand "status", "pause" and "resume".

import AppKit

struct Target: Decodable {
    let name: String
    let allowed: UInt64
    let denied: UInt64
    let last_unix: UInt64?
}

struct Status: Decodable {
    let paused: Bool
    let bind: String
    let uptime_s: UInt64
    /// Seconds since anything was last forwarded, or since start or the last
    /// resume. Optional so an older proxy still shows up instead of as down.
    let idle_s: UInt64?
    let targets: [Target]
}

struct Instance {
    let socket: String
    let status: Status
}

/// Each instance puts a `control-<port>.sock` here.
let controlDir = NSHomeDirectory() + "/.config/agentic-credential-proxy"

/// Off by default; remembered across restarts.
let autoPauseKey = "autoPauseWhenIdle"
let idleLimit: UInt64 = 6 * 3600

/// One command, one JSON line back. Nil means nothing answered, which for a
/// socket file left behind by a stopped instance is the normal case.
func send(_ command: String, to socketPath: String) -> Status? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }

    var timeout = timeval(tv_sec: 2, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let path = Array(socketPath.utf8)
    guard path.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
    withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: path) }
    let connected = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard connected == 0 else { return nil }

    let line = Array((command + "\n").utf8)
    guard write(fd, line, line.count) == line.count else { return nil }

    var data = Data()
    var buf = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(fd, &buf, buf.count)
        if n <= 0 { break }
        data.append(buf, count: n)
    }
    return try? JSONDecoder().decode(Status.self, from: data)
}

/// Every instance that answers, in port order.
func runningInstances() -> [Instance] {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: controlDir)) ?? []
    return names
        .filter { $0.hasPrefix("control-") && $0.hasSuffix(".sock") }
        .sorted()
        .compactMap { name in
            let socket = controlDir + "/" + name
            return send("status", to: socket).map { Instance(socket: socket, status: $0) }
        }
}

func ago(_ seconds: UInt64) -> String {
    switch seconds {
    case ..<60: return "\(seconds)s"
    case ..<3600: return "\(seconds / 60)m"
    case ..<86400: return "\(seconds / 3600)h"
    default: return "\(seconds / 86400)d"
    }
}

@MainActor
final class MenuBar: NSObject, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var instances: [Instance] = []

    override init() {
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        refresh()
        // Only so the icon notices a restart or a stop; the menu itself always
        // asks fresh when it is opened.
        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        instances = runningInstances()
        if UserDefaults.standard.bool(forKey: autoPauseKey) {
            instances = instances.map { inst in
                guard !inst.status.paused, let idle = inst.status.idle_s, idle >= idleLimit,
                      let paused = send("pause", to: inst.socket)
                else { return inst }
                return Instance(socket: inst.socket, status: paused)
            }
        }

        let pausedCount = instances.filter { $0.status.paused }.count
        let (symbol, label) =
            switch (instances.count, pausedCount) {
            case (0, _): ("exclamationmark.triangle", "proxy not running")
            case let (n, p) where p == n: ("pause.circle.fill", "proxy paused")
            case (_, 0): ("key.fill", "proxy forwarding")
            case (let n, let p): ("key.fill", "\(p) of \(n) instances paused")
            }
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        image?.isTemplate = true
        item.button?.image = image
        item.button?.toolTip = "agentic-credential-proxy: \(label)"
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        menu.removeAllItems()

        if instances.isEmpty {
            menu.addItem(info("Proxy not running"))
            menu.addItem(info("no control socket answering in \(controlDir)"))
        }

        let now = UInt64(Date().timeIntervalSince1970)
        for (i, inst) in instances.enumerated() {
            let s = inst.status
            if i > 0 { menu.addItem(.separator()) }
            menu.addItem(info(s.paused ? "⏸ Paused — \(s.bind)" : "● Forwarding on \(s.bind)"))
            menu.addItem(info("up \(ago(s.uptime_s))" + (s.idle_s.map { " · idle \(ago($0))" } ?? "")))
            for t in s.targets {
                let last = t.last_unix.map { "\(ago(now.saturatingSub($0))) ago" } ?? "never"
                menu.addItem(info("    \(t.name)   \(t.allowed) ok · \(t.denied) denied · \(last)"))
            }
            let toggle = menu.addItem(
                withTitle: s.paused ? "Resume forwarding" : "Pause forwarding",
                action: #selector(toggle(_:)), keyEquivalent: "")
            toggle.target = self
            toggle.representedObject = inst.socket
        }

        menu.addItem(.separator())
        let auto = menu.addItem(
            withTitle: "Auto-pause after \(idleLimit / 3600)h without forwarding",
            action: #selector(toggleAutoPause), keyEquivalent: "")
        auto.target = self
        auto.state = UserDefaults.standard.bool(forKey: autoPauseKey) ? .on : .off
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit", action: #selector(quit), keyEquivalent: "q").target = self
    }

    /// Enabled but without an action: a disabled item is drawn greyed out,
    /// which makes the numbers hard to read. Clicking one just closes the menu.
    func info(_ title: String) -> NSMenuItem {
        NSMenuItem(title: title, action: nil, keyEquivalent: "")
    }

    @objc func toggle(_ sender: NSMenuItem) {
        guard let socket = sender.representedObject as? String else { return }
        let paused = instances.first { $0.socket == socket }?.status.paused == true
        _ = send(paused ? "resume" : "pause", to: socket)
        refresh()
    }

    /// Turning it on while already idle past the limit pauses straight away,
    /// which is the point. It applies to every instance.
    @objc func toggleAutoPause() {
        let defaults = UserDefaults.standard
        defaults.set(!defaults.bool(forKey: autoPauseKey), forKey: autoPauseKey)
        refresh()
    }

    @objc func quit() {
        NSApp.terminate(nil)
    }
}

extension UInt64 {
    func saturatingSub(_ other: UInt64) -> UInt64 { self > other ? self - other : 0 }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let menuBar = MenuBar()
    app.run()
    _ = menuBar
}
