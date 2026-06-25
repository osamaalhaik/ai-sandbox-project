import tempfile
import unittest
from pathlib import Path

from app.security.audit import build_gateway_record, decision_status
from app.security.context import build_command_context
from app.security.decision import make_decision
from app.sandbox.policy import SandboxCommandPolicy


class ContextAwareSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.workspace = self.root / "data" / "workspaces" / "default"
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_workspace_destructive_command_is_allowed_with_monitoring(self):
        command = ["rm", "-rf", "data/workspaces/default/cache"]
        context = build_command_context(command, self.root, self.workspace)
        decision = make_decision(context)

        self.assertTrue(context.has_workspace_target)
        self.assertFalse(context.has_outside_workspace_target)
        self.assertEqual(decision.decision, "allow_with_monitoring")
        self.assertEqual(decision.risk_score, 25)
        self.assertEqual(decision.risk_level, "low")
        self.assertTrue(decision.can_execute)
        self.assertFalse(decision.requires_confirmation)

    def test_outside_workspace_destructive_command_requires_confirmation(self):
        command = ["rm", "-rf", "./cache"]
        context = build_command_context(command, self.root, self.workspace)
        decision = make_decision(context)

        self.assertFalse(context.has_workspace_target)
        self.assertTrue(context.has_outside_workspace_target)
        self.assertEqual(decision.decision, "require_confirmation")
        self.assertEqual(decision.risk_score, 70)
        self.assertEqual(decision.risk_level, "high")
        self.assertTrue(decision.can_execute)
        self.assertTrue(decision.requires_confirmation)

    def test_critical_system_command_is_blocked(self):
        command = ["rm", "-rf", "/etc"]
        context = build_command_context(command, self.root, self.workspace)
        decision = make_decision(context)

        self.assertTrue(context.has_sensitive_target)
        self.assertTrue(context.has_system_target)
        self.assertEqual(decision.decision, "block_critical")
        self.assertEqual(decision.risk_score, 100)
        self.assertEqual(decision.risk_level, "critical")
        self.assertFalse(decision.can_execute)
        self.assertFalse(decision.requires_confirmation)

    def test_root_path_is_blocked_as_critical(self):
        command = ["rm", "-rf", "/"]
        context = build_command_context(command, self.root, self.workspace)
        decision = make_decision(context)

        self.assertTrue(context.has_system_target)
        self.assertEqual(decision.decision, "block_critical")
        self.assertEqual(decision.risk_score, 100)
        self.assertEqual(decision.risk_level, "critical")
        self.assertFalse(decision.can_execute)

    def test_sandbox_policy_uses_context_aware_decision_for_rm(self):
        policy = SandboxCommandPolicy()

        inside = policy.validate(["rm", "-rf", "data/workspaces/default/cache"], str(self.root))
        outside = policy.validate(["rm", "-rf", "./cache"], str(self.root))
        critical = policy.validate(["rm", "-rf", "/etc"], str(self.root))

        self.assertTrue(inside.allowed)
        self.assertEqual(inside.security_decision, "allow_with_monitoring")
        self.assertEqual(inside.risk_score, 25)

        self.assertFalse(outside.allowed)
        self.assertEqual(outside.reason, "confirmation_required")
        self.assertEqual(outside.security_decision, "require_confirmation")
        self.assertEqual(outside.risk_score, 70)

        self.assertFalse(critical.allowed)
        self.assertEqual(critical.security_decision, "block_critical")
        self.assertEqual(critical.risk_score, 100)

    def test_gateway_audit_statuses(self):
        allowed_context = build_command_context(["rm", "-rf", "data/workspaces/default/cache"], self.root, self.workspace)
        pending_context = build_command_context(["rm", "-rf", "./cache"], self.root, self.workspace)
        denied_context = build_command_context(["rm", "-rf", "/etc"], self.root, self.workspace)

        allowed_decision = make_decision(allowed_context)
        pending_decision = make_decision(pending_context)
        denied_decision = make_decision(denied_context)

        self.assertEqual(decision_status(allowed_decision), "approved_for_execution")
        self.assertEqual(decision_status(pending_decision), "pending_confirmation")
        self.assertEqual(decision_status(denied_decision), "denied")

        record = build_gateway_record(["rm", "-rf", "./cache"], pending_context, pending_decision)

        self.assertEqual(record["security_decision"], "require_confirmation")
        self.assertEqual(record["decision_status"], "pending_confirmation")
        self.assertEqual(record["risk_score"], 70)
        self.assertEqual(record["risk_level"], "high")


if __name__ == "__main__":
    unittest.main()
