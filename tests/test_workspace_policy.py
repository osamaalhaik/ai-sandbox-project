import unittest

from app.security.workspace_policy import assess_workspace_path


class WorkspacePolicyTests(unittest.TestCase):
    def test_relative_path_inside_workspace_is_allowed_for_destructive_action(self):
        result = assess_workspace_path("cache", "data/workspaces/default")

        self.assertEqual(result.classification, "inside_workspace")
        self.assertTrue(result.allowed_for_destructive_action)
        self.assertFalse(result.requires_human_review)
        self.assertFalse(result.should_block)

    def test_parent_traversal_outside_workspace_requires_review(self):
        result = assess_workspace_path("../outside-cache", "data/workspaces/default")

        self.assertEqual(result.classification, "outside_workspace")
        self.assertFalse(result.allowed_for_destructive_action)
        self.assertTrue(result.requires_human_review)
        self.assertFalse(result.should_block)

    def test_sensitive_path_requires_human_review(self):
        result = assess_workspace_path("/etc/passwd", "data/workspaces/default")

        self.assertEqual(result.classification, "sensitive_path")
        self.assertFalse(result.allowed_for_destructive_action)
        self.assertTrue(result.requires_human_review)
        self.assertFalse(result.should_block)

    def test_critical_path_is_blocked(self):
        result = assess_workspace_path("/etc", "data/workspaces/default")

        self.assertEqual(result.classification, "critical_path")
        self.assertFalse(result.allowed_for_destructive_action)
        self.assertFalse(result.requires_human_review)
        self.assertTrue(result.should_block)


if __name__ == "__main__":
    unittest.main()
