"""Tool manifests - the least-privilege declaration for every tool (§4 Rule 5).

A manifest is data, not code. It states the narrowest thing true about a tool:
which arguments steer *what the action does to the outside world* (the control
plane), whether the tool can move data out of the system, whether it is
destructive, and which named sanitizer may declassify each argument.

The control-plane / data-plane split is the central policy decision here. An
argument like `send_email.to` decides where data goes; `send_email.body` is the
data itself. Untrusted text reaching `body` is ordinary and expected - it is how
"summarise this web page and mail it to me" works. Untrusted text reaching `to`
is an attacker choosing the destination. Only the second is a provenance
violation; confidentiality of the payload is enforced separately, by the
trajectory invariants. This mirrors the control-flow integrity argument in CaMeL
(arXiv:2503.18813). See docs/decisions.md D-05.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolManifest:
    """Declared, immutable capability description for one tool."""

    name: str
    description: str
    args: tuple[str, ...]
    critical_args: tuple[str, ...] = ()      # control-plane arguments
    egress: bool = False                     # can move data outside the system
    destructive: bool = False                # irreversible effect
    reads_resources: bool = False            # brings outside content into context
    sanitizers: dict[str, str] = field(default_factory=dict)  # arg -> sanitizer name

    def validate(self, args: dict) -> tuple[bool, str]:
        """Check the call's argument names against the declaration.

        On failure: the checkpoint denies at the MANIFEST layer. Unknown
        arguments are refused rather than ignored, because an ignored argument is
        an unaudited one.
        """
        unknown = set(args) - set(self.args)
        if unknown:
            return False, f"undeclared argument(s) {sorted(unknown)} for tool {self.name}"
        return True, ""


TOOL_MANIFESTS: dict[str, ToolManifest] = {m.name: m for m in (
    ToolManifest(
        name="read_file",
        description="Read a file from the sandbox workspace.",
        args=("path",), critical_args=("path",), reads_resources=True,
        sanitizers={"path": "sandbox_path"},
    ),
    ToolManifest(
        name="list_files",
        description="List files in a sandbox directory.",
        args=("dir",), critical_args=("dir",), reads_resources=True,
        sanitizers={"dir": "sandbox_path"},
    ),
    ToolManifest(
        name="fetch_url",
        description="Fetch a document from the simulated web.",
        args=("url",), critical_args=("url",), reads_resources=True,
        sanitizers={"url": "url_allowlist"},
    ),
    ToolManifest(
        name="search_docs",
        description="Search the simulated document store.",
        args=("query",), reads_resources=True,
    ),
    ToolManifest(
        name="send_email",
        description="Send an email (mocked: written to sandbox/outbox).",
        args=("to", "subject", "body"), critical_args=("to",), egress=True,
        sanitizers={"to": "email_allowlist", "body": "no_confidential_leak"},
    ),
    ToolManifest(
        name="http_post",
        description="POST data to a URL (mocked: written to sandbox/outbox).",
        args=("url", "payload"), critical_args=("url",), egress=True,
        sanitizers={"url": "url_allowlist", "payload": "no_confidential_leak"},
    ),
    ToolManifest(
        name="make_payment",
        description="Initiate a payment (mocked: recorded, never executed).",
        args=("recipient", "amount", "memo"), critical_args=("recipient", "amount"),
        egress=True, destructive=True,
        sanitizers={"recipient": "email_allowlist", "amount": "numeric_range",
                    "memo": "no_confidential_leak"},
    ),
    ToolManifest(
        name="write_file",
        description="Write a file inside the sandbox workspace.",
        args=("path", "content"), critical_args=("path",),
        sanitizers={"path": "sandbox_path"},
    ),
    ToolManifest(
        name="delete_file",
        description="Delete a file inside the sandbox workspace.",
        args=("path",), critical_args=("path",), destructive=True,
        sanitizers={"path": "sandbox_path"},
    ),
)}


@dataclass
class AgentManifest:
    """The scope granted to one agent session (§4 Rule 5).

    `allowed_tools` is the whole grant: a tool absent from it cannot be called
    even if every other layer would permit the call.
    """

    allowed_tools: tuple[str, ...]
    egress_budget: int = 1

    def permits(self, tool: str) -> tuple[bool, str]:
        if tool not in TOOL_MANIFESTS:
            return False, f"tool {tool!r} is not a declared tool"
        if tool not in self.allowed_tools:
            return False, (f"tool {tool!r} is outside this agent's granted scope "
                           f"{sorted(self.allowed_tools)}")
        return True, ""


DEFAULT_AGENT_MANIFEST = AgentManifest(
    allowed_tools=("read_file", "list_files", "fetch_url", "search_docs",
                   "send_email", "http_post", "write_file"),
    egress_budget=1,
)
