"""Client for the agentic credential proxy.

Stdlib only, so it runs on the agent machine with no pip install.

    export ACP_URL=http://100.101.102.103:8788

    from acp import ACP
    acp = ACP()
    r = acp.post("elevenlabs/v1/text-to-speech/<voice id>", json={"text": "hello"})
    r.save("hello.mp3")

This machine holds no credentials of any kind -- not the API key, and not a
token for the proxy either. Reachability over the tailnet is the authorisation,
enforced by Tailscale ACLs on the proxy's port.
"""

from __future__ import annotations

import json as _json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

__all__ = ["ACP", "ACPError", "Response"]


class ACPError(RuntimeError):
    """An upstream or proxy error. `.status` and `.body` carry the details."""

    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"{status} from {url}: {body[:2000]}")
        self.status = status
        self.body = body
        self.url = url


class Response:
    def __init__(self, status: int, headers: Mapping[str, str], content: bytes, url: str):
        self.status = status
        self.headers = headers
        self.content = content
        self.url = url

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self.content)

    def save(self, path: str) -> str:
        """Write the raw body to disk. For image/audio/video endpoints."""
        with open(path, "wb") as fh:
            fh.write(self.content)
        return path

    def __repr__(self) -> str:
        ctype = self.headers.get("content-type", "?")
        return f"<Response {self.status} {ctype} {len(self.content)}B>"


class ACP:
    def __init__(self, url: str | None = None, timeout: float = 300.0):
        self.url = (url or os.environ.get("ACP_URL") or "").rstrip("/")
        self.timeout = timeout
        if not self.url:
            raise ACPError(0, "set ACP_URL or pass url=", "<unset>")

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        raise_for_status: bool = True,
    ) -> Response:
        if json is not None and data is not None:
            raise ValueError("pass json= or data=, not both")

        url = f"{self.url}/{path.lstrip('/')}"
        sent: dict[str, str] = {}

        # The proxy requires the provider to be named in a header as well as in
        # the path, and refuses the request if the two disagree. Deriving it from
        # the path here means the two can only disagree if the caller overrides
        # it deliberately via headers=.
        provider = path.lstrip("/").split("/")[0]
        if provider and provider not in ("healthz", "providers", "files"):
            sent["X-ACP-Provider"] = provider

        if json is not None:
            data = _json.dumps(json).encode()
            sent["Content-Type"] = "application/json"
        sent.update(headers or {})

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=sent)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                out = Response(resp.status, dict(resp.headers), resp.read(), url)
        except urllib.error.HTTPError as e:
            # An upstream 4xx/5xx: the body is the provider's error message and
            # is the most useful thing to surface.
            out = Response(e.code, dict(e.headers or {}), e.read(), url)
        except urllib.error.URLError as e:
            raise ACPError(0, f"could not reach the proxy: {e.reason}", url) from None

        if raise_for_status and out.status >= 400:
            raise ACPError(out.status, out.text, url)
        return out

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw: Any) -> Response:
        return self.request("PUT", path, **kw)

    def delete(self, path: str, **kw: Any) -> Response:
        return self.request("DELETE", path, **kw)

    def discover(self) -> dict:
        """The full discovery document: routes, upstreams, descriptions, docs."""
        return self.get("/").json()

    def providers(self) -> list[str]:
        """Just the provider names, e.g. ['elevenlabs', 'openai']."""
        return [p["name"] for p in self.discover()["providers"]]

    # --- the one-way file drop, if the proxy has it enabled -------------------

    def files(self) -> list[dict]:
        """What is waiting for you: [{'name', 'bytes', 'modified_unix'}, ...].

        Raises ACPError with a 404 if this proxy has no file share.
        """
        return self.get("/files").json()["files"]

    def take(self, name: str, dest: str | None = None) -> str:
        """Fetch one file and write it here, returning the local path.

        The proxy deletes its copy once the whole file has gone out, so this
        works exactly once per file. If it fails part way the proxy keeps the
        file, so retrying is safe.
        """
        r = self.get("files/" + urllib.parse.quote(name, safe=""))
        return r.save(dest or os.path.basename(name))

    def take_all(self, dest_dir: str = ".") -> list[str]:
        """Drain the drop directory into `dest_dir`."""
        os.makedirs(dest_dir, exist_ok=True)
        return [
            self.take(f["name"], os.path.join(dest_dir, os.path.basename(f["name"])))
            for f in self.files()
        ]


if __name__ == "__main__":
    doc = ACP().discover()
    for p in doc["providers"]:
        desc = f"  # {p['description']}" if p.get("description") else ""
        print(f"{p['route']:<32} -> {p['upstream']}{desc}")
    if "files" in doc:
        waiting = ACP().files()
        print(f"{'/files':<32} -> {len(waiting)} file(s) waiting; fetching one deletes it")
        for f in waiting:
            print(f"    {f['name']}  ({f['bytes']} bytes)")
