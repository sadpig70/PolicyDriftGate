#!/usr/bin/env python3
"""Deterministic sample packets for PolicyDriftGate."""

import copy
import json

from .verifier import digest_public_surface

CLEARED_PACKET = {
    "audit_id": "AUDIT-CLEARED-001",
    "audit_time": "2026-07-02T00:00:00+00:00",
    "behavior": {
        "baseline_hash": "a68f04b2b3a1a1f0a12e3e4a5b6c7d8e9f01a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
        "candidate_hash": "a68f04b2b3a1a1f0a12e3e4a5b6c7d8e9f01a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
        "drift_metric": 0.05,
        "threshold": 0.20,
        "evidence_path": "evidence/behavior/AUDIT-CLEARED-001.json"
    },
    "dossier": {
        "approved_baseline_version": "1.0.0",
        "logs_analyzed": 1000,
        "non_compliance_count": 0,
        "evidence_path": "evidence/dossier/AUDIT-CLEARED-001.json"
    },
    "runtime_signal": {
        "loop_detected": False,
        "attestation_issued": False,
        "evidence_path": "evidence/signal/AUDIT-CLEARED-001.json"
    },
    "trace": {
        "digest": "",
        "evidence_path": "evidence/trace/AUDIT-CLEARED-001.sha256"
    }
}

WARNED_PACKET = copy.deepcopy(CLEARED_PACKET)
WARNED_PACKET["audit_id"] = "AUDIT-WARNED-001"
WARNED_PACKET["behavior"]["candidate_hash"] = "b592c3a4d5e6f7a8b9c0d1e2f3a4b5a68f04b2b3a1a1f0a12e3e4a5b6c7d8e9f"
WARNED_PACKET["behavior"]["drift_metric"] = 0.17
WARNED_PACKET["runtime_signal"]["loop_detected"] = True
WARNED_PACKET["runtime_signal"]["evidence_path"] = "evidence/signal/AUDIT-WARNED-001.json"
WARNED_PACKET["trace"]["evidence_path"] = "evidence/trace/AUDIT-WARNED-001.sha256"

INTERRUPTED_PACKET = copy.deepcopy(CLEARED_PACKET)
INTERRUPTED_PACKET["audit_id"] = "AUDIT-INTERRUPTED-001"
INTERRUPTED_PACKET["behavior"]["candidate_hash"] = "c331a4b5a68f04b2b3a1a1f0a12e3e4a5b6c7d8e9fb592c3a4d5e6f7a8b9c0d1"
INTERRUPTED_PACKET["behavior"]["drift_metric"] = 0.25
INTERRUPTED_PACKET["dossier"]["non_compliance_count"] = 3
INTERRUPTED_PACKET["runtime_signal"]["loop_detected"] = True
INTERRUPTED_PACKET["runtime_signal"]["attestation_issued"] = True
INTERRUPTED_PACKET["runtime_signal"]["evidence_path"] = "evidence/signal/AUDIT-INTERRUPTED-001.json"
INTERRUPTED_PACKET["trace"]["evidence_path"] = "evidence/trace/AUDIT-INTERRUPTED-001.sha256"


def _bound(packet):
    packet = copy.deepcopy(packet)
    # We can omit trace digest when computing digest to avoid self-reference
    packet["trace"]["digest"] = digest_public_surface(packet)
    return packet


CLEARED_PACKET = _bound(CLEARED_PACKET)
WARNED_PACKET = _bound(WARNED_PACKET)
INTERRUPTED_PACKET = _bound(INTERRUPTED_PACKET)


def samples():
    return {
        "cleared": copy.deepcopy(CLEARED_PACKET),
        "warned": copy.deepcopy(WARNED_PACKET),
        "interrupted": copy.deepcopy(INTERRUPTED_PACKET),
    }


def write_samples(out_dir):
    import os

    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for name, packet in samples().items():
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(packet, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        written[name] = path
    return written
