# Threshold

Threshold is a defensive security alert triage and investigation engine.

V0.1 accepts simulated Linux authentication and post-authentication events, normalizes them, detects SSH brute-force activity, creates alerts, correlates relevant events, and returns an investigation timeline.

Detection is deterministic and isolated in `detections/`. No AI decision-making, autonomous response, external integrations, frontend, database, Docker configuration, or Jev integration is included.

## Supported investigation scenario

The built-in simulator represents one deterministic Linux SSH investigation:

```text
five failed SSH logins from one source IP to one host
→ successful SSH login from the same source IP to that host
→ command execution and file access on that host
```

Correlation requires the detected source IP, target host, a supported investigation event type, and a timestamp between the first failed attempt and 15 minutes after the final failed attempt. Post-authentication activity must follow a successful SSH login in that scope. The simulator includes unrelated events to demonstrate their exclusion.

All timestamps must include a timezone. Threshold converts them to UTC internally and returns UTC timestamps.

## Project layout

- `app/` — FastAPI application, shared event and alert schemas, normalization, correlation, and investigation orchestration.
- `detections/` — deterministic detection rules; this layer does not call AI or API code.
- `simulator/` — synthetic Linux security-event generators for local development.
- `tests/` — pytest coverage for detection and triage workflows.
- `docs/` — architecture notes and operational documentation.
- `data/` — local/generated data, excluded from Git except its placeholder.

## Development

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
pytest
```

Start the API:

```powershell
uvicorn app.main:app --reload
```

The health endpoint is `GET /health`; submit events to `POST /investigations`.

## Architectural separation

- `normalization` validates and converts inbound payloads into domain events.
- `detections` contains deterministic rules only; it has no AI behavior.
- `correlation` applies explicit source, host, time, and event-type criteria.
- `investigation` creates a chronological timeline from correlated events.
- `workflow` coordinates those deterministic stages.

Any future AI decision support belongs after this workflow and must not participate in raw event detection.
