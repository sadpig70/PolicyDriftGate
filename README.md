# PolicyDriftGate

> Verify behavior policy baseline drift and interrupt execution loops at runtime.

## One-sentence pitch

`PolicyDriftGate` answers: *Can an AI agent deployment prove it remains aligned with its behavior policy baseline, and is any abnormal execution loop immediately interrupted with an auditable attestation?*

## Why this matters

As autonomous AI agents run continuously, two failure modes occur: behavior drift from baseline policies, and abnormal loop events. Pre-approval checks are not enough. We need a deterministic, real-time safety gate that cross-validates behavior drift and deployment logs while providing a reflex-like loop interruption attestation when unsafe patterns emerge.

`PolicyDriftGate` is a stdlib-only CLI and Python package for enforcing this safety boundary.

## What it is not

- Not an agent orchestration platform.
- Not a general model-evaluation harness.
- Not a prompt-engineering framework.
- Not a live policy generator.

It verifies runtime audit packets and issues deterministic verdicts.

## Install / Run

Requires Python 3.10+ and no external packages.

From this project root:

```bash
python -m pip install -e .
python -m PolicyDriftGate sample --out examples
python -m PolicyDriftGate run --input examples/cleared.json
python -m PolicyDriftGate report --input examples/cleared.json --out examples/cleared.report.md
```

## Closed-audit ledger

`run --ledger PATH` appends a deterministic, append-only hash-chain record to a `ledger.jsonl` file. `verify --ledger PATH` checks the chain integrity and detects tampering. This turns the CLI into a closed audit loop:

```
sample -> run --ledger -> append record -> verify --ledger
```

```bash
# Append a verdict record
python -m PolicyDriftGate run --input examples/cleared.json --ledger examples/ledger.jsonl
python -m PolicyDriftGate run --input examples/warned.json --ledger examples/ledger.jsonl
python -m PolicyDriftGate run --input examples/interrupted.json --ledger examples/ledger.jsonl

# Verify the chain (exit code 0 = valid, 1 = tampered)
python -m PolicyDriftGate verify --ledger examples/ledger.jsonl
```

Each ledger record is one JSON line:

```json
{
  "index": 0,
  "audit_id": "AUDIT-CLEARED-001",
  "verdict": "cleared",
  "aggregate_digest": "...",
  "result_hash": "...",
  "prev_hash": "",
  "record_hash": "..."
}
```

Hash rules:
- `result_hash` — sha256 of the canonical JSON of the full verdict result.
- `record_hash` — sha256 of the canonical JSON of the record excluding `record_hash`.
- Each next record stores the previous `record_hash` in `prev_hash` (the first record uses `""`).

`verify` returns:
```json
{ "valid": true, "records": 3, "error": "" }
```

## Packet format

An audit packet is JSON with these top-level sections:
- `audit_id` and `audit_time`
- `behavior` — baseline_hash, candidate_hash, drift_metric, threshold, and evidence_path.
- `dossier` — approved_baseline_version, logs_analyzed, non_compliance_count, and evidence_path.
- `runtime_signal` — loop_detected, attestation_issued, and evidence_path.

Private payload fields such as `payload`, `private_payload`, `raw_payload`, `secret`, or `secrets` are rejected.

## Verdict scheme

- `cleared` — all required safety predicates are satisfied.
- `warned` — minor drift or incomplete loop metadata detected, but loop is stable.
- `interrupted` — significant drift or active loop detected, resulting in immediate execution interruption.

The aggregate verdict is the highest severity across all checks, with active loop interruption taking absolute precedence.

## Python API

```python
from PolicyDriftGate import evaluate_policy_drift

result = evaluate_policy_drift(packet)
print(result["verdict"])
```

Ledger API:
```python
from PolicyDriftGate import append_record, verify_ledger

append_record("ledger.jsonl", result)
print(verify_ledger("ledger.jsonl"))  # {"valid": True, "records": 1, "error": ""}
```

## Tests

From this project root:
```bash
python -m unittest discover -s tests -q
```

## License

MIT License — see [LICENSE](LICENSE).
