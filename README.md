# agentic-credential-proxy

A small HTTP proxy that lets an agent call credentialed APIs without ever holding
the credential. The agent can run on this Mac (loopback) or on another machine on
your tailnet.

The agent sends `POST /elevenlabs/v1/text-to-speech/...`. The proxy pulls the
`elevenlabs` key out of the macOS login keychain, sets the header that provider
wants, and streams the request to `https://api.elevenlabs.io/v1/text-to-speech/...`.
Bodies are never parsed, so any API works; a new provider is a few lines of TOML.
An optional [one-way file drop](#the-file-drop) lets the agent take files off
this Mac, and a [menu bar app](#the-menu-bar) shows counters and can pause it all.

```
agent                        this Mac                          upstream API
  python acp.py ──loopback──▶ proxy :8788                           │
  no credentials  or tailnet  ├─ key from login keychain            │
                              └─ inject header, forward ───────────▶│
```

## Security model

The key never leaves the keychain on this Mac. A compromised agent can
*spend* your credits but cannot *exfiltrate the key*.

**There is no inbound authentication, deliberately.** A token would have to live
wherever the agent runs, which is exactly what this proxy keeps credential-free,
and an attacker controlling that environment could make the calls anyway.
Reachability is the authorisation, and the bind picks one of two modes:

- **Loopback** (`127.0.0.1`, `::1`), for an agent on this Mac. Every local
  process can reach it, under any user account on the Mac. See
  [a local agent](#a-local-agent) for what it can and cannot do beyond that.
- **Tailnet** (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`), for an agent on another
  machine. The [Tailscale ACL](#the-acl) is the actual access control.

Anything else, such as a LAN address or `0.0.0.0`, is a startup error.

**Tailnet is the safer mode.** There the agent is on another machine and never
touches this Mac's keychain, configs or processes. On loopback it shares the
Mac with the key. The proxy is hardened for that, but the last line of defence
is you noticing a keychain prompt you did not cause. If you can, run a local
agent as a separate macOS user.

**Requests must be addressed to the bind address.** The `Host` header must be the
bind IP and port, or `localhost:<port>` on a loopback bind; anything else is
`403 deny-host`, on every route. This stops DNS rebinding, where a web page in
a browser that can reach the port points its own domain at the proxy to use it
as same-origin. Use the IP in `ACP_URL`, not a MagicDNS name.

Anything that reaches the port gets every provider, minus what `deny_paths` /
`allow_paths` rule out. Not enforced: client identity, rate limits, spend caps.

Not configurable, because getting them wrong leaks the credential itself:

- **Upstreams must be https and not on this Mac.** `localhost`, loopback and
  `0.0.0.0` upstreams are refused in any spelling, because a local process could
  take the port first and be handed the key.
- **TRACE and CONNECT are never forwarded** (`405`): an upstream honouring TRACE
  echoes the injected header back to the agent.
- **Redirects are never followed.** A redirect would carry a custom credential
  header like `xi-api-key` to wherever it points, and would step around
  `deny_paths`. The `3xx` goes back to the agent to re-issue through the proxy.
- **Proxy environment variables are ignored.** `HTTP_PROXY`, `HTTPS_PROXY` and
  `ALL_PROXY` never reroute a request, whatever shell the proxy was started from.

### A local agent

The keychain trusts one exact binary, and anything that changes it raises the
approval prompt again. So a keychain prompt you did not cause is the signal
that something is off. The proxy is built so that, short of such a prompt, an
agent running as you cannot change where a key goes:

- **The config is built into the binary.** `--config` only selects one of the
  configs embedded at build time, and a file that does not match one byte for
  byte is refused. Editing a config, or writing a new one, needs a rebuild.
- **The binary is signed with the hardened runtime** (`start.sh` does this), so
  macOS refuses `DYLD_INSERT_LIBRARIES` and debugger attach. Code cannot be run
  inside the trusted binary without a re-sign, which prompts again.
- **No other runtime input steers it.** Proxy environment variables and
  `RUST_LOG` are ignored.

A rebuild embeds whatever configs are on disk at that moment, and the build
output names each one (`embedding ...`). The prompt after a rebuild you started
is expected, so read that list before approving it. A local agent can still
spend your credits, stop the proxy, flip the pause switch, and raise prompts
you might approve by mistake. Running it as a separate macOS user puts it
outside all of that.

### X-ACP-Provider

Every proxied request must carry `X-ACP-Provider` naming the same provider as the
path, or it is a `400` with `deny-mismatch`, before any keychain access. Not a
security control, but an anti-hallucination check: a wrong provider has to be
guessed twice. It is stripped before forwarding; `client/acp.py` sets it for you.

### deny_paths, allow_paths, allow_methods

```toml
[[providers]]
name = "elevenlabs"
deny_paths = ["v1/user*", "v1/history*", "*api-key*"]   # 403 deny-path
allow_paths = ["v1/text-to-speech*", "v1/voices*"]      # 403 deny-unlisted; optional, exhaustive if present
allow_methods = ["GET", "POST"]                         # 405 deny-method; optional
```

Rules are matched against the path the request **will be sent with**: the
upstream URL is built first (resolving `.`/`..` and `%2e`), then percent-decoded
once, lowercased, with repeated and trailing slashes collapsed. So `/v1/./user`,
`/v1%2Fuser`, `/V1/User` and `/v1//user/` all hit `v1/user*`. A path resolving
outside the provider's base URL is `400 deny-traversal`. `*` spans anything,
including `/`, and is greedy on purpose: over-blocking is the safe direction.

Deny is checked first, and all checks run before the credential is read. A
denylist does not cover endpoints a provider adds later; an allowlist does, at
the cost of maintaining it. Both lists are advertised on discovery.

### The file drop

Optional. Point the proxy at one directory and the agent can list it and take
files out of it, nothing more: no upload, write, rename or mkdir.

```toml
[files]
dir = "~/acp-drop"      # must exist
# enabled = false
```

`GET /files` lists what is waiting; `GET /files/<name>` returns the bytes and
deletes the file after the last byte (audit: `consumed`). A broken transfer
leaves the file in place; a concurrent fetch of the same file is a `409`.

Containment:

- **A name is one segment.** `/`, `\`, a leading dot and control characters are
  refused, after a single percent-decode.
- **Only plain files.** Opened with `O_NOFOLLOW | O_NONBLOCK`, so a symlink is
  refused by the kernel at open time (no check-then-open race) and a fifo cannot
  park the request. The type is then confirmed on the descriptor.
- **No hard links.** `nlink > 1` is skipped and refused, since
  `ln ~/.ssh/id_rsa drop/x` would otherwise pass every other check.
- **The directory is resolved once at startup**, and each fetch re-checks that
  the result is still a direct child.
- **The listing only names what a fetch would serve**; the rest is a `skipped` count.

Stage files with `cp` + `mv` (atomic, single link), never `ln`. Anything that
can already write the directory as you is inside the trust boundary; keep it
dedicated to the drop.

### The ACL

Tailnet mode only. Grant only the agent machine access to the port:

```jsonc
{ "acls": [ { "action": "accept", "src": ["tag:agent"], "dst": ["<this mac>:8788"] } ] }
```

Without it, a default-open tailnet lets *every* device you own reach the proxy.

## Setup

One keychain item per provider, named after it. No `-A`, so only this binary
gets access, after one approval prompt:

```sh
security add-generic-password -s agentic-credential-proxy -a elevenlabs -w "<api key>" -U
```

Config lives at `~/.config/agentic-credential-proxy/config.toml`:

```sh
mkdir -p ~/.config/agentic-credential-proxy
cp config.example.toml ~/.config/agentic-credential-proxy/config.toml
$EDITOR ~/.config/agentic-credential-proxy/config.toml   # bind = 127.0.0.1:8788, or `tailscale ip -4`
./start.sh --check     # builds, validates config, reads every key, does not bind
./start.sh             # run it
```

`./start.sh` builds the proxy and the menu bar app only when their binaries are
missing, or on `--rebuild`. **Every config change needs `./start.sh --rebuild`**,
since configs are built into the binary. That embeds the `config.toml` of every
`~/.config/agentic-credential-proxy*` directory, so a second instance just
needs its own directory and `--config` pointing into it. Run `--check` from a
terminal first so the keychain prompts appear where you can click "Always
Allow". A rebuilt binary prompts again, and its first keychain read takes a few
seconds.

### Adding a provider

```toml
[[providers]]
name = "elevenlabs"
base_url = "https://api.elevenlabs.io"
header = "xi-api-key"
header_value = "{credential}"       # default "Bearer {credential}"
description = "text to speech"      # optional, shown on discovery
# docs, deny_paths, allow_paths, allow_methods: optional
# keychain_account = "..."          # defaults to the name
# extra_headers = { "api-version" = "2023-06-01" }
```

Then `./start.sh --rebuild`. Unknown fields are a startup error, so typos fail
loudly. Names may not be `healthz`, `providers` or `files`.

## Calling it

`client/acp.py` is stdlib-only; copy it to wherever the agent runs.

```python
from acp import ACP                 # ACP_URL=http://127.0.0.1:8788 or http://<tailnet ip>:8788
acp = ACP()
acp.get("elevenlabs/v1/voices").json()
acp.files()                         # what is in the drop
acp.take("render.png")              # fetch it; the Mac's copy is deleted
acp.take_all("inbox/")
```

Non-2xx raises `ACPError` with the upstream's error body (`raise_for_status=False`
to opt out). With curl, send the header yourself:

```sh
curl -H 'x-acp-provider: elevenlabs' $ACP_URL/elevenlabs/v1/voices
```

| Route | |
|---|---|
| `GET /` (`/providers`) | discovery: providers, upstreams, path rules, file-drop usage |
| `GET /healthz` | liveness only |
| `GET /files`, `GET /files/<name>` | the file drop, if enabled |
| `ANY /<provider>/<path>` | forwarded; requires `X-ACP-Provider` |

Discovery is non-secret by construction. It never names the credential header
or the drop directory.

Headers pass through except hop-by-hop ones, `Host`, `X-ACP-Provider`, the
client's `Authorization` and the credential header, so a caller cannot smuggle
in a credential of their own. Responses are never decompressed.

## Operating it

**Rotate a key:** `security add-generic-password ... -U`, run `--check` and approve
the prompt, then `kill -HUP` the proxy to reload keys without a restart. Config
changes need `./start.sh --rebuild`.

**Audit log**, one line per request on stderr (header values are never logged,
and secrets print as `<redacted>`):
`allow`, `deny-provider`, `deny-mismatch`, `deny-path`, `deny-unlisted`,
`deny-method`, `deny-traversal`, `deny-host`, `deny-credential`, `error`. From the file drop:
`deny-name`, `deny-file`, `deny-busy`, `consumed`. From pausing: `deny-paused`,
`paused`, `resumed`.

Run it from a terminal in your logged-in session. The keychain must be unlocked,
and its prompts need somewhere to appear.

### The menu bar

`./start.sh` also starts a small menu bar app (`menubar/ACPMenuBar.swift`, built
with `swiftc`, no dependencies) and quits it when the proxy exits. It shows
per-provider counters and idle time for every running instance, and has two
switches:

- **Pause forwarding.** Every proxied and file-drop request becomes `503
  deny-paused`; discovery and `/healthz` still answer. In-flight requests
  finish. Held in memory, so a restart comes back forwarding.
- **Auto-pause after 6h without forwarding.** Off by default and remembered
  across restarts. Only requests that were let through count as activity, and
  resuming restarts the clock.

It is a separate process so no GUI code lives in the binary that reads the
keychain. It holds no credentials and opens no port. It talks to each instance
over `~/.config/agentic-credential-proxy/control-<port>.sock`, a Unix socket
that is unreachable from the network. The socket is `0600` in a `0700` directory, and the
proxy also checks the caller's uid. The socket understands `status`, `pause` and
`resume`:

```sh
echo pause | nc -U ~/.config/agentic-credential-proxy/control-8788.sock
```

The pause is a switch for you, not a boundary against something already running
as you on this Mac.

## License

Apache-2.0, see [LICENSE](LICENSE).
