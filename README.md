# Threshold

Threshold is a deterministic defensive-security alert triage and investigation engine. V0.2 processes simulated security events, detects defined activity patterns, creates alerts, correlates bounded related events, and builds a chronological investigation timeline.

## Supported event types

Every event has a strict common envelope: event ID, timezone-aware timestamp, target host, outcome, optional source IP and username, event type, and event-specific `details`. Timestamps are normalized to UTC.

- `ssh_login` uses authentication details (`method: "ssh"`).
- `web_request` uses web details: HTTP method, path, and response status.
- `command_execution`, `process_start`, `file_access`, and `privilege_escalation` use process details with a named action.

Unknown event fields and unknown detail fields are rejected. V0.1-style SSH events without `details` remain accepted and normalize to SSH authentication details.

## Detection rules

| Rule | Detection | Explicit threshold/window |
|---|---|---|
| `THR-DET-001` | SSH brute force | Five failed SSH logins from one source IP to one host within five minutes. |
| `THR-DET-002` | Brute force followed by SSH success | A same-IP, same-host SSH success more than the final failed attempt and within 15 minutes of a THR-DET-001 window. |
| `THR-DET-003` | Web reconnaissance | Three distinct paths from `/.env`, `/.git/config`, `/wp-admin`, and `/phpmyadmin`, from one source IP to one host within five minutes. |
| `THR-DET-004` | Suspicious post-authentication activity | One of `download_tool`, `add_user`, or `disable_logging`, from the same IP, host, and user after THR-DET-002 within 15 minutes. |

## Correlation

Correlation always re-checks normalized event fields; a detection match is a candidate, not unquestionable evidence.

- SSH investigations require matching source IP, host, bounded timestamps, and relevant SSH/process activity. Process activity must follow a successful SSH login for the same user.
- Web investigations require matching source IP, host, triggering time window, and a sensitive-path web request.
- Events from other hosts, source IPs, users where relevant, unrelated event types, or outside the rule window are excluded.

## Simulator scenarios

`simulator/linux_auth.py` provides deterministic scenarios for:

- SSH brute force only
- SSH brute force followed by successful authentication
- SSH brute force, success, and suspicious post-auth activity
- Benign SSH activity
- Web reconnaissance
- Benign web browsing
- Unrelated activity for correlation-exclusion tests

## Architecture

- `app/normalization.py` validates input and normalizes event timestamps and structure.
- `detections/` contains deterministic rules with stable IDs.
- `app/workflow.py` registers rules with declared dependencies and runs each when prerequisites are available; independent rules do not depend on an SSH sequence.
- `app/correlation.py` applies explicit, rule-aware correlation bounds.
- `app/investigation.py` creates the timeline.

Future AI decision support, if introduced, belongs after this deterministic workflow. It must not perform raw event detection.

## Development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Start the API:

```powershell
uvicorn app.main:app --reload
```

Use `GET /health` for a health check and `POST /investigations` to submit an event batch.
