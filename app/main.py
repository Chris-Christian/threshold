"""HTTP API for the deterministic Threshold workflow."""

from fastapi import FastAPI
from pydantic import BaseModel

from .models import Investigation, SecurityEventInput
from .workflow import triage

app = FastAPI(title="Threshold", version="0.2.0")


class TriageRequest(BaseModel):
    events: list[SecurityEventInput]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/investigations", response_model=Investigation)
def create_investigation(request: TriageRequest) -> Investigation:
    return triage(request.events)
