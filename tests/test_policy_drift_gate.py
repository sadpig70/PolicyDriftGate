#!/usr/bin/env python3
"""Stdlib-only tests for the standalone PolicyDriftGate package."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Dynamic path resolution to support execution from package tests and root tests
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.basename(ROOT) == "PolicyDriftGate":
    SRC = os.path.join(ROOT, "src")
    PROJECT_ROOT = ROOT
else:
    SRC = os.path.join(ROOT, "PolicyDriftGate", "src")
    PROJECT_ROOT = os.path.join(ROOT, "PolicyDriftGate")

if SRC not in sys.path:
    sys.path.insert(0, SRC)
ENV = {**os.environ, "PYTHONPATH": SRC}

from PolicyDriftGate.samples import samples
from PolicyDriftGate.verifier import (
    digest_public_surface,
    evaluate_policy_drift,
    has_private_payload,
)
from PolicyDriftGate.ledger import append_record, verify_ledger


class TestPolicyDriftGateStandalone(unittest.TestCase):
    def test_sample_verdicts(self):
        docs = samples()
        self.assertEqual(evaluate_policy_drift(docs["cleared"])["verdict"], "cleared")
        self.assertEqual(evaluate_policy_drift(docs["warned"])["verdict"], "warned")
        self.assertEqual(evaluate_policy_drift(docs["interrupted"])["verdict"], "interrupted")

    def test_deterministic_repeated_run(self):
        packet = samples()["cleared"]
        self.assertEqual(evaluate_policy_drift(packet), evaluate_policy_drift(packet))

    def test_private_payload_is_rejected(self):
        packet = samples()["cleared"]
        packet["private_payload"] = {"secret_token": "leak"}
        self.assertTrue(has_private_payload(packet))
        self.assertEqual(evaluate_policy_drift(packet)["verdict"], "interrupted")

    def test_major_behavioral_drift_causes_interrupted(self):
        packet = samples()["cleared"]
        packet["behavior"]["drift_metric"] = 0.21
        packet["trace"]["digest"] = digest_public_surface(packet, omit_trace_digest=True)
        result = evaluate_policy_drift(packet)
        self.assertEqual(result["verdict"], "interrupted")
        self.assertIn("drift", [c for c in result["checks"] if c["name"] == "behavior"][0]["reason"])

    def test_minor_behavioral_drift_causes_warned(self):
        packet = samples()["cleared"]
        packet["behavior"]["drift_metric"] = 0.17
        packet["trace"]["digest"] = digest_public_surface(packet, omit_trace_digest=True)
        result = evaluate_policy_drift(packet)
        self.assertEqual(result["verdict"], "warned")

    def test_loop_detected_overrides_policy_cleared(self):
        packet = samples()["cleared"]
        packet["runtime_signal"]["loop_detected"] = True
        packet["runtime_signal"]["attestation_issued"] = True
        packet["trace"]["digest"] = digest_public_surface(packet, omit_trace_digest=True)
        result = evaluate_policy_drift(packet)
        self.assertEqual(result["verdict"], "interrupted")

    def test_trace_digest_binds_public_surface(self):
        packet = samples()["cleared"]
        packet["behavior"]["drift_metric"] = 0.08
        result = evaluate_policy_drift(packet)
        self.assertEqual(result["verdict"], "interrupted")
        self.assertIn("public surface", [c for c in result["checks"] if c["name"] == "trace"][0]["reason"])

    def test_cli_sample_run_report(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "sample", "--out", d],
                cwd=PROJECT_ROOT,
                env=ENV,
                text=True,
            )
            cleared_file = os.path.join(d, "cleared.json")
            out = subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "run", "--input", cleared_file],
                cwd=PROJECT_ROOT,
                env=ENV,
                text=True,
            )
            self.assertEqual(json.loads(out)["verdict"], "cleared")
            report = subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "report", "--input", cleared_file],
                cwd=PROJECT_ROOT,
                env=ENV,
                text=True,
            )
            self.assertIn("# PolicyDriftGate Report", report)
            self.assertIn("behavior", report)

    def test_cli_strict_returns_nonzero_for_warned(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "sample", "--out", d],
                cwd=PROJECT_ROOT,
                env=ENV,
                text=True,
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "PolicyDriftGate",
                    "run",
                    "--input",
                    os.path.join(d, "warned.json"),
                    "--strict",
                ],
                cwd=PROJECT_ROOT,
                env=ENV,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout)["verdict"], "warned")


class TestLedger(unittest.TestCase):
    def test_append_after_run_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            for name in ("cleared", "warned", "interrupted"):
                packet = samples()[name]
                result = evaluate_policy_drift(packet)
                rec = append_record(ledger, result)
                self.assertEqual(rec["index"], {"cleared": 0, "warned": 1, "interrupted": 2}[name])
                self.assertTrue(rec["record_hash"])
            result = verify_ledger(ledger)
            self.assertTrue(result["valid"])
            self.assertEqual(result["records"], 3)
            self.assertEqual(result["error"], "")

    def test_run_with_ledger_flag_appends(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "sample", "--out", d],
                cwd=PROJECT_ROOT, env=ENV, text=True,
            )
            ledger = os.path.join(d, "ledger.jsonl")
            subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "run",
                 "--input", os.path.join(d, "cleared.json"), "--ledger", ledger],
                cwd=PROJECT_ROOT, env=ENV, text=True,
            )
            verify = json.loads(subprocess.check_output(
                [sys.executable, "-m", "PolicyDriftGate", "verify", "--ledger", ledger],
                cwd=PROJECT_ROOT, env=ENV, text=True,
            ))
            self.assertTrue(verify["valid"])
            self.assertEqual(verify["records"], 1)

    def test_tampered_ledger_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_policy_drift(samples()["cleared"]))
            append_record(ledger, evaluate_policy_drift(samples()["warned"]))
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[1])
            rec["verdict"] = "interrupted"
            lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertIn("record_hash mismatch", result["error"])

    def test_broken_chain_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_policy_drift(samples()["cleared"]))
            append_record(ledger, evaluate_policy_drift(samples()["warned"]))
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[1])
            rec["prev_hash"] = "deadbeef" * 8
            lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            result = verify_ledger(ledger)
            self.assertFalse(result["valid"])
            self.assertIn("prev_hash mismatch", result["error"])

    def test_cli_verify_returns_nonzero_on_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = os.path.join(d, "ledger.jsonl")
            append_record(ledger, evaluate_policy_drift(samples()["cleared"]))
            with open(ledger, "r", encoding="utf-8") as f:
                lines = f.readlines()
            rec = json.loads(lines[0])
            rec["verdict"] = "warned"
            lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n"
            with open(ledger, "w", encoding="utf-8") as f:
                f.writelines(lines)
            proc = subprocess.run(
                [sys.executable, "-m", "PolicyDriftGate", "verify", "--ledger", ledger],
                cwd=PROJECT_ROOT, env=ENV, text=True, capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(json.loads(proc.stdout)["valid"])


if __name__ == "__main__":
    unittest.main()
