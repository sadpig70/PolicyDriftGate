#!/usr/bin/env python3
"""Deterministic AI behavior policy and loop safety verifier (stdlib only)."""

import copy
import hashlib
import json
import re

SEVERITY = {"cleared": 0, "warned": 1, "interrupted": 2}
PRIVATE_KEYS = {"payload", "private_payload", "raw_payload", "secret", "secrets"}
EVIDENCE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _check(name, verdict, reason, evidence_path=""):
    return {
        "name": name,
        "verdict": verdict,
        "reason": reason,
        "evidence_path": evidence_path or "",
    }


def cleared(name, evidence_path):
    return _check(name, "cleared", "predicate satisfied", evidence_path)


def warned(name, reason, evidence_path=""):
    return _check(name, "warned", reason, evidence_path)


def interrupted(name, reason, evidence_path=""):
    return _check(name, "interrupted", reason, evidence_path)


def missing(required, obj):
    if not isinstance(obj, dict):
        return list(required)
    return [k for k in required if k not in obj or obj[k] in ("", None)]


def thin_or_breach(name, missing_fields):
    fields = ", ".join(missing_fields)
    if "evidence_path" in missing_fields:
        return interrupted(name, f"missing evidence path; also missing: {fields}")
    return warned(name, f"missing fields: {fields}")


def is_sha256_hex(value):
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def valid_evidence_path(value):
    text = str(value or "")
    if not text or text.startswith(("/", "\\")) or ".." in text.replace("\\", "/").split("/"):
        return False
    return bool(EVIDENCE_PATH_RE.fullmatch(text)) and text.replace("\\", "/").startswith("evidence/")


def has_private_payload(value):
    if isinstance(value, dict):
        for key, sub in value.items():
            if str(key).lower() in PRIVATE_KEYS:
                return True
            if has_private_payload(sub):
                return True
    elif isinstance(value, list):
        return any(has_private_payload(item) for item in value)
    return False


def _public_copy(value, omit_trace_digest=False, path=()):
    if isinstance(value, dict):
        return {
            k: _public_copy(v, omit_trace_digest, path + (str(k),))
            for k, v in sorted(value.items())
            if str(k).lower() not in PRIVATE_KEYS
            and not (omit_trace_digest and path == ("trace",) and str(k) == "digest")
        }
    if isinstance(value, list):
        return [_public_copy(v, omit_trace_digest, path) for v in value]
    return value


def digest_public_surface(packet, omit_trace_digest=True):
    public = _public_copy(packet, omit_trace_digest=omit_trace_digest)
    payload = json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def invalid_evidence_path_check(name, evidence_path):
    if not valid_evidence_path(evidence_path):
        return interrupted(name, "invalid evidence path", evidence_path)
    return None


def check_behavior(packet):
    behavior = packet.get("behavior", {})
    required = ["baseline_hash", "candidate_hash", "drift_metric", "threshold", "evidence_path"]
    miss = missing(required, behavior)
    if miss:
        return thin_or_breach("behavior", miss)
    invalid = invalid_evidence_path_check("behavior", behavior.get("evidence_path"))
    if invalid:
        return invalid

    if not is_sha256_hex(behavior.get("baseline_hash")):
        return interrupted("behavior", "invalid baseline_hash sha256 hex", behavior["evidence_path"])
    if not is_sha256_hex(behavior.get("candidate_hash")):
        return interrupted("behavior", "invalid candidate_hash sha256 hex", behavior["evidence_path"])

    drift = behavior.get("drift_metric", 0.0)
    threshold = behavior.get("threshold", 0.0)
    
    if drift > threshold:
        return interrupted("behavior", f"behavior policy drift {drift} exceeds threshold {threshold}", behavior["evidence_path"])
    if drift > threshold * 0.8:
        return warned("behavior", f"behavior policy drift {drift} approaching threshold {threshold}", behavior["evidence_path"])
    
    return cleared("behavior", behavior.get("evidence_path"))


def check_dossier(packet):
    dossier = packet.get("dossier", {})
    required = ["approved_baseline_version", "logs_analyzed", "non_compliance_count", "evidence_path"]
    miss = missing(required, dossier)
    if miss:
        return thin_or_breach("dossier", miss)
    invalid = invalid_evidence_path_check("dossier", dossier.get("evidence_path"))
    if invalid:
        return invalid

    non_compliance = dossier.get("non_compliance_count", 0)
    if non_compliance > 0:
        return interrupted("dossier", f"detected {non_compliance} non-compliance events in dossier", dossier["evidence_path"])
    
    return cleared("dossier", dossier.get("evidence_path"))


def check_loop_signal(packet):
    signal = packet.get("runtime_signal", {})
    required = ["loop_detected", "attestation_issued", "evidence_path"]
    miss = missing(required, signal)
    if miss:
        return thin_or_breach("loop_signal", miss)
    invalid = invalid_evidence_path_check("loop_signal", signal.get("evidence_path"))
    if invalid:
        return invalid

    if signal.get("loop_detected") is True:
        if signal.get("attestation_issued") is not True:
            return warned("loop_signal", "abnormal loop detected but attestation not yet issued", signal["evidence_path"])
        return interrupted("loop_signal", "abnormal loop detected and safety interrupted", signal["evidence_path"])
    
    return cleared("loop_signal", signal.get("evidence_path"))


def check_trace(packet):
    trace = packet.get("trace", {})
    if has_private_payload(packet):
        return interrupted("trace", "packet contains private payload field", trace.get("evidence_path", ""))
    if not trace.get("digest") or not trace.get("evidence_path"):
        return warned("trace", "trace digest or evidence_path missing", trace.get("evidence_path", ""))
    invalid = invalid_evidence_path_check("trace", trace.get("evidence_path"))
    if invalid:
        return invalid
    if not is_sha256_hex(trace.get("digest")):
        return interrupted("trace", "trace digest is not sha256 hex", trace.get("evidence_path"))
    expected = digest_public_surface(packet, omit_trace_digest=True)
    if trace.get("digest") != expected:
        return interrupted("trace", "trace digest does not bind public surface", trace.get("evidence_path"))
    return cleared("trace", trace.get("evidence_path"))


def evaluate_policy_drift(packet):
    """Evaluate behavior policy, deployment dossier, and runtime loop signal safety."""
    if has_private_payload(packet):
        return {
            "audit_id": packet.get("audit_id", ""),
            "verdict": "interrupted",
            "checks": [_check("private_payload", "interrupted", "packet contains private payload field")],
            "aggregate_digest": "",
        }

    checks = [
        check_behavior(packet),
        check_dossier(packet),
        check_loop_signal(packet),
        check_trace(packet),
    ]

    # Real-time loop detection interruption takes absolute precedence
    loop_check = next((c for c in checks if c["name"] == "loop_signal"), None)
    if loop_check and loop_check["verdict"] == "interrupted":
        verdict = "interrupted"
    else:
        # Otherwise aggregate by worst severity
        worst_sev = -1
        verdict = "cleared"
        for check in checks:
            sev = SEVERITY.get(check["verdict"], 0)
            if sev > worst_sev:
                worst_sev = sev
                verdict = check["verdict"]

    return {
        "audit_id": packet.get("audit_id", ""),
        "verdict": verdict,
        "checks": checks,
        "aggregate_digest": digest_public_surface(packet, omit_trace_digest=True),
    }


def render_markdown(result):
    lines = [
        f"# PolicyDriftGate Report — {result.get('audit_id', '')}",
        "",
        f"- verdict: {result['verdict']}",
        f"- aggregate_digest: `{result.get('aggregate_digest', '')}`",
        "",
        "## Checks",
        "",
        "| check | verdict | evidence_path | reason |",
        "|---|---|---|---|",
    ]
    for c in result.get("checks", []):
        lines.append(f"| {c['name']} | {c['verdict']} | `{c['evidence_path']}` | {c['reason']} |")
    lines.append("")
    return "\n".join(lines)
