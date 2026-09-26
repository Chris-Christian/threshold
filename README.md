# Threshold

Threshold is a deterministic defensive-security alert triage, investigation, and detection-quality evaluation engine. V0.4 uses only synthetic inputs and fixed deterministic rules; it includes no Jev, AI/LLMs, database, frontend, Docker, external integration, or autonomous response.

## Detection and event model

Events use a strict common envelope with timezone-aware timestamps normalized to UTC, plus typed details for SSH authentication, web requests, and process activity. Unknown fields are rejected.

| Rule | Behavior |
|---|---|
| `THR-DET-001` | Five failed SSH logins from one source IP to one host within five minutes. |
| `THR-DET-002` | A matching SSH success within 15 minutes after a brute-force window. |
| `THR-DET-003` | Three distinct sensitive web paths from one source IP to one host within five minutes. |
| `THR-DET-004` | A documented suspicious action after the matching successful SSH authentication. |

Detection remains independent of future decision-support systems. Dependent rules re-check normalized events; a previous match is a candidate, not unquestionable evidence.

## V0.3 investigations

Threshold creates one investigation per connected correlated-alert cluster. Alerts join a case only when correlated event-ID sets overlap, including transitively; unrelated SSH and web activity therefore stay separate.

Evidence and timelines are compact, immutable analyst-facing views derived from normalized source events. Investigations start `OPEN`, can move to `INVESTIGATING`, then to terminal `RESOLVED`. Resolution requires one analyst outcome: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN`, or `INCONCLUSIVE`.

Alert IDs are deterministic UUID5 values derived from the rule ID, scope, detection window, and triggering event IDs. Investigation IDs are new UUID4 values. Investigation lifecycle state is held only in process memory and is lost when the API restarts.

## V0.4 evaluation

The separate `evaluation/` package benchmarks rule quality without creating alerts, correlation output, or investigations:

```text
labeled scenario → normalize_events() → run_detections() → comparison → metrics
```

One deterministic labeled event sequence is one evaluation unit. Every scenario explicitly declares `expected_rule_ids`; ground truth is never inferred from detector output, alerts, investigations, or simulator behavior. The benchmark includes malicious, benign, mixed, below-threshold, exact-threshold, and outside-window SSH/web cases and is intentionally separate from the traffic simulator.

For each rule and scenario, metrics use one-vs-rest labels:

```text
TP: expected and observed      FP: not expected and observed
FN: expected and not observed  TN: not expected and not observed
```

`precision = TP / (TP + FP)` and `recall = TP / (TP + FN)` when their denominators are non-zero. `F1 = 2PR / (P + R)` when both measures are defined and their sum is positive. Undefined metrics are represented as `null`/`None`, never `0.0`.

These metrics describe performance on the fixed synthetic evaluation dataset and are not claims about production detection accuracy.

## Project layout

- `app/` — validation, workflow, correlation, investigations, and FastAPI endpoints.
- `detections/` — deterministic detection rules.
- `simulator/` — synthetic traffic generation for development and detection tests.
- `evaluation/` — labeled benchmark scenarios, evaluation models, and runner.
- `tests/` — unit, workflow, investigation, and evaluation tests.

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Start the API with `uvicorn app.main:app --reload`. The API exposes `GET /health`, `POST /investigations`, and focused in-memory investigation lifecycle endpoints. V0.4 intentionally adds no evaluation HTTP endpoint.
