import unittest

from app.security.execution_profiles import (
    profile_for_strategy,
)


class ExecutionProfileTests(
    unittest.TestCase
):
    def test_execution_strategy_mapping(self):
        expected = {
            "lightweight_sandbox": (
                "low"
            ),
            (
                "workspace_sandbox_"
                "with_monitoring"
            ): "standard",
            "restricted_sandbox": (
                "standard"
            ),
            "strong_sandbox": (
                "intensive"
            ),
            (
                "restricted_sandbox_"
                "with_confirmation"
            ): "intensive",
        }

        for strategy, profile_name in (
            expected.items()
        ):
            with self.subTest(
                strategy=strategy
            ):
                self.assertEqual(
                    profile_for_strategy(
                        strategy
                    ).name,
                    profile_name,
                )

    def test_unknown_strategy_is_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            profile_for_strategy(
                "unknown_strategy"
            )

        with self.assertRaises(
            ValueError
        ):
            profile_for_strategy(
                "do_not_execute"
            )

    def test_profile_resource_limits_are_valid(self):
        for strategy in (
            "lightweight_sandbox",
            "restricted_sandbox",
            "strong_sandbox",
        ):
            profile = (
                profile_for_strategy(
                    strategy
                )
            )

            limits = (
                profile.resource_limits()
            )

            limits.validate()

            self.assertGreater(
                limits.memory_max_bytes,
                0,
            )

            self.assertGreater(
                limits.pids_max,
                0,
            )


if __name__ == "__main__":
    unittest.main()
