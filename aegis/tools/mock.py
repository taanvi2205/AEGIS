"""Mocked tool implementations (§5).

Nothing here touches a real external system. Email is written to a local outbox
file, payments are recorded as intent, network fetches are served from an
in-memory document set supplied by the scenario, and all file access is confined
to the sandbox directory. This is the only place a tool actually "acts", and it
is reached only after the checkpoint has allowed the call.

Extension point for a real integration (§5): `EgressAdapter` below is the single
seam where one real, harmless outbound action could later be wired in. It is
deliberately left unimplemented - `RealEgressAdapter` does not exist in this
repo, and the mock adapter is the only implementation shipped.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .manifests import TOOL_MANIFESTS


class EgressAdapter:
    """Seam for outbound actions. Implementations must be explicitly opted into.

    The base implementation raises: an adapter that has not been chosen cannot
    silently become the default (§5).
    """

    def deliver(self, kind: str, payload: dict) -> dict:
        raise NotImplementedError("no egress adapter selected")


@dataclass
class MockEgressAdapter(EgressAdapter):
    """Records intended outbound actions to sandbox/outbox as JSON. Never
    contacts any network."""

    outbox: Path

    def deliver(self, kind: str, payload: dict) -> dict:
        self.outbox.mkdir(parents=True, exist_ok=True)
        rec = {"kind": kind, "ts": time.time(), "payload": payload, "delivered": False,
               "note": "mocked - recorded locally, never sent"}
        path = self.outbox / f"{kind}-{int(time.time() * 1e6)}.json"
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return {"recorded": str(path), "delivered": False}


@dataclass
class ToolWorld:
    """The sandboxed world the mocked tools operate on.

    `documents` maps a URL or search key to (text, confidential). Scenarios
    populate it; nothing is fetched from the real network, ever.
    """

    root: Path
    documents: dict[str, tuple[str, bool]] = field(default_factory=dict)
    files: dict[str, tuple[str, bool]] = field(default_factory=dict)
    adapter: EgressAdapter | None = None

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        if self.adapter is None:
            self.adapter = MockEgressAdapter(self.root / "outbox")

    # -- ingress tools ---------------------------------------------------
    def read_file(self, path: str) -> dict:
        if path not in self.files:
            return {"ok": False, "error": f"no such file in sandbox: {path}"}
        text, confidential = self.files[path]
        return {"ok": True, "content": text, "confidential": confidential,
                "source_ref": f"file://{path}"}

    def list_files(self, dir: str) -> dict:                      # noqa: A002 - matches manifest
        names = [p for p in self.files if p.startswith(dir.rstrip("/"))]
        return {"ok": True, "content": "\n".join(names), "confidential": False,
                "source_ref": f"file://{dir}"}

    def fetch_url(self, url: str) -> dict:
        if url not in self.documents:
            return {"ok": False, "error": f"no such document: {url}"}
        text, confidential = self.documents[url]
        return {"ok": True, "content": text, "confidential": confidential,
                "source_ref": url}

    def search_docs(self, query: str) -> dict:
        hits = [f"{k}: {v[0][:120]}" for k, v in self.documents.items()
                if any(w in v[0].lower() for w in query.lower().split())]
        return {"ok": True, "content": "\n".join(hits) or "no results",
                "confidential": any(v[1] for v in self.documents.values()),
                "source_ref": f"search://{query}"}

    # -- egress / mutation tools ----------------------------------------
    def send_email(self, to: str, subject: str = "", body: str = "") -> dict:
        out = self.adapter.deliver("email", {"to": to, "subject": subject, "body": body})
        return {"ok": True, **out}

    def http_post(self, url: str, payload: str = "") -> dict:
        out = self.adapter.deliver("http_post", {"url": url, "payload": payload})
        return {"ok": True, **out}

    def make_payment(self, recipient: str, amount: str = "0", memo: str = "") -> dict:
        out = self.adapter.deliver("payment",
                                   {"recipient": recipient, "amount": amount, "memo": memo})
        return {"ok": True, **out}

    def write_file(self, path: str, content: str = "") -> dict:
        self.files[path] = (content, False)
        return {"ok": True, "wrote": path, "bytes": len(content)}

    def delete_file(self, path: str) -> dict:
        existed = self.files.pop(path, None) is not None
        return {"ok": existed, "deleted": path if existed else None}

    def invoke(self, tool: str, args: dict) -> dict:
        """Dispatch to a mocked tool by name.

        Only tools present in TOOL_MANIFESTS are dispatchable; anything else
        raises rather than being reflected onto an attribute, so a model-supplied
        string can never reach an arbitrary method (§4 Rule 6).
        """
        if tool not in TOOL_MANIFESTS:
            raise KeyError(f"undeclared tool {tool!r}")
        fn = {
            "read_file": self.read_file, "list_files": self.list_files,
            "fetch_url": self.fetch_url, "search_docs": self.search_docs,
            "send_email": self.send_email, "http_post": self.http_post,
            "make_payment": self.make_payment, "write_file": self.write_file,
            "delete_file": self.delete_file,
        }[tool]
        return fn(**args)
