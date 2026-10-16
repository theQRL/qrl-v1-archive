"""End-to-end checks of the throwaway-key action v2 fixture."""

import unittest
from pathlib import Path

import signer_fixture


class SignerFixtureTests(unittest.TestCase):
    def test_action_v2_contract_and_mutation_rejections(self) -> None:
        action = Path.home() / "actions-mldsa-sign"
        qrlft = Path.home() / "qrlft"
        self.assertTrue(action.is_dir(), f"missing local action checkout: {action}")
        self.assertTrue(qrlft.is_dir(), f"missing local qrlft checkout: {qrlft}")

        report = signer_fixture.exercise(action, qrlft)

        self.assertEqual(report["tool_fixture"], "PASS")
        self.assertEqual(report["release_readiness"], "FAIL")
        self.assertFalse(report["org_key_used"])
        self.assertFalse(report["action_image_tested"])
        self.assertTrue(all(report["checks"].values()))
        for case in (
            "artifact tail mutation rejected",
            "manifest mutation rejected",
            "tag mutation rejected",
            "wrong key rejected",
            "wrong artifact context rejected",
            "wrong manifest context rejected",
        ):
            self.assertIn(case, report["checks"])


if __name__ == "__main__":
    unittest.main()
