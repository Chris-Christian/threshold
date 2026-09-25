"""HTTP API for the deterministic Threshold workflow."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .investigation import InMemoryInvestigationStore
from .models import Investigation, InvestigationBatch, InvestigationOutcome, SecurityEventInput
from .workflow import triage

app = FastAPI(title="Threshold", version="0.3.0")
store = InMemoryInvestigationStore()


class TriageRequest(BaseModel):
    events: list[SecurityEventInput]


class ResolveRequest(BaseModel):
    outcome: InvestigationOutcome


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/investigations", response_model=InvestigationBatch)
def create_investigations(request: TriageRequest) -> InvestigationBatch:
    return store.add_batch(triage(request.events))


@app.get("/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: str) -> Investigation:
    investigation = store.get(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return investigation


@app.post("/investigations/{investigation_id}/start", response_model=Investigation)
def start_investigation(investigation_id: str) -> Investigation:
    try:
        return store.begin(investigation_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="investigation not found") from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/investigations/{investigation_id}/resolve", response_model=Investigation)
def resolve_investigation_endpoint(investigation_id: str, request: ResolveRequest) -> Investigation:
    try:
        return store.resolve(investigation_id, request.outcome)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="investigation not found") from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
