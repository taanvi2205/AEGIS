"""Every error path must deny, never allow (§3, fail closed)."""

import unittest

from aegis.audit import AuditLog
from aegis.checkpoint.checkpoint import CONFIGS, Checkpoint
from aegis.checkpoint.classifier import Guard, GuardResult, build_guard
from aegis.checkpoint.sanitizers import Sanitizer, default_registry
from aegis.checkpoint.trajectory import Invariant, SessionState
from aegis.core import Content, Label, ToolCall, Verdict
from aegis.tools.manifests import TOOL_MANIFESTS


class ExplodingGuard(Guard):
    name = "exploding"

    def classify(self, content):
        raise RuntimeError("model unavailable")


class ExplodingSanitizer(Sanitizer):
    def __init__(self):
        super().__init__("exploding", "always raises")

    def _check(self, value, context=None):
        raise RuntimeError("boom")


class ExplodingInvariant(Invariant):
    def __init__(self):
        super().__init__("INV-X:exploding", "always raises")

    def check(self, state, call, tool, findings):
        raise RuntimeError("boom")


class TestFailClosed(unittest.TestCase):
    def test_guard_error_flags_content(self):
        r = ExplodingGuard().screen("anything")
        self.assertTrue(r.flagged)
        self.assertIn("RuntimeError", r.error)

    def test_guard_error_quarantines_at_ingest(self):
        cp = Checkpoint(config=CONFIGS["full"], guard=ExplodingGuard(), audit=AuditLog())
        admitted, _ = cp.ingest(Content("d", "document", "u", "harmless text", Label.UNTRUSTED), 1)
        self.assertFalse(admitted, "an unavailable guard must not admit content")

    def test_sanitizer_error_does_not_clear_taint(self):
        rec = ExplodingSanitizer().run("value")
        self.assertFalse(rec.passed)
        self.assertIn("failing closed", rec.checked)

    def test_invariant_error_is_a_violation(self):
        violated, why = ExplodingInvariant().evaluate(
            SessionState(), ToolCall("send_email", {}), TOOL_MANIFESTS["send_email"], [])
        self.assertTrue(violated)
        self.assertIn("failing closed", why)

    def test_checkpoint_exception_blocks(self):
        """An exception anywhere in evaluation produces BLOCK, not ALLOW."""
        cp = Checkpoint(config=CONFIGS["full"], guard=build_guard("heuristic"),
                        audit=AuditLog(), invariants=[ExplodingInvariant()])
        cp.ingest(Content("task", "user_task", "user", "Email bob@corp.example.", Label.TRUSTED))
        d = cp.evaluate(ToolCall("send_email", {"to": "bob@corp.example", "subject": "s",
                                                "body": "b"}, step=1))
        self.assertIs(d.verdict, Verdict.BLOCK)

    def test_undeclared_tool_is_blocked_even_with_policy_off(self):
        cp = Checkpoint(config=CONFIGS["none"], guard=build_guard("heuristic"), audit=AuditLog())
        d = cp.evaluate(ToolCall("rm_rf", {"path": "/"}, step=1))
        self.assertIs(d.verdict, Verdict.BLOCK)

    def test_unregistered_sanitizer_does_not_clear_taint(self):
        reg = default_registry()
        self.assertIsNone(reg.get("no_such_sanitizer"))


if __name__ == "__main__":
    unittest.main()
