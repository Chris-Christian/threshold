"""Build and manage small, in-memory analyst-facing investigations."""

from datetime import datetime, timezone
from uuid import uuid4

from .models import (
    AlertCorrelation, EvidenceItem, Investigation, InvestigationBatch,
    InvestigationOutcome, InvestigationStatus, SecurityEvent, TimelineEntry,
)


def _event_summary(event: SecurityEvent) -> str:
    return f"{event.event_type} {event.outcome} on {event.host}"


def build_evidence(events: list[SecurityEvent]) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            event_id=event.event_id, timestamp=event.timestamp, host=event.host,
            source_ip=event.source_ip, username=event.username,
            event_type=event.event_type, outcome=event.outcome,
            details=event.details, summary=_event_summary(event),
        )
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id))
    ]


def build_timeline(events: list[SecurityEvent]) -> list[TimelineEntry]:
    return [TimelineEntry(**item.model_dump()) for item in build_evidence(events)]


def _connected_clusters(correlations: list[AlertCorrelation]) -> list[list[AlertCorrelation]]:
    """Group alerts by direct or transitive correlated event-ID overlap."""
    pending = list(correlations)
    clusters = []
    while pending:
        cluster = [pending.pop(0)]
        cluster_event_ids = set(cluster[0].correlated_event_ids)
        changed = True
        while changed:
            changed = False
            for correlation in pending[:]:
                if cluster_event_ids.intersection(correlation.correlated_event_ids):
                    cluster.append(correlation)
                    cluster_event_ids.update(correlation.correlated_event_ids)
                    pending.remove(correlation)
                    changed = True
        clusters.append(cluster)
    return clusters


def build_investigations(events: list[SecurityEvent], correlations: list[AlertCorrelation]) -> InvestigationBatch:
    """Create one OPEN investigation per connected correlated-alert cluster."""
    events_by_id = {event.event_id: event for event in events}
    for correlation in correlations:
        if not correlation.correlated_event_ids:
            raise ValueError("alert correlations require at least one correlated event ID")
        unknown_event_ids = set(correlation.correlated_event_ids).difference(events_by_id)
        if unknown_event_ids:
            raise ValueError(
                f"alert correlation contains unknown event IDs: {sorted(unknown_event_ids)}"
            )
    investigations = []
    for cluster in _connected_clusters(correlations):
        event_ids = sorted({event_id for correlation in cluster for event_id in correlation.correlated_event_ids})
        correlated_events = [events_by_id[event_id] for event_id in event_ids]
        investigations.append(
            Investigation(
                investigation_id=str(uuid4()), created_at=datetime.now(timezone.utc),
                alerts=[correlation.alert for correlation in cluster],
                correlated_event_ids=event_ids, evidence=build_evidence(correlated_events),
                timeline=build_timeline(correlated_events),
            )
        )
    return InvestigationBatch(investigations=investigations)


def _with_updates(investigation: Investigation, **updates: object) -> Investigation:
    values = investigation.model_dump()
    values.update(updates)
    return Investigation.model_validate(values)


def begin_investigation(investigation: Investigation) -> Investigation:
    if investigation.status != InvestigationStatus.OPEN:
        raise ValueError("only OPEN investigations can transition to INVESTIGATING")
    return _with_updates(investigation, status=InvestigationStatus.INVESTIGATING)


def resolve_investigation(investigation: Investigation, outcome: InvestigationOutcome | None) -> Investigation:
    if investigation.status != InvestigationStatus.INVESTIGATING:
        raise ValueError("only INVESTIGATING investigations can transition to RESOLVED")
    if outcome is None:
        raise ValueError("resolving an investigation requires an outcome")
    return _with_updates(investigation, status=InvestigationStatus.RESOLVED, outcome=outcome)


class InMemoryInvestigationStore:
    """Deliberately small process-local storage for V0.3 lifecycle operations."""

    def __init__(self) -> None:
        self._investigations: dict[str, Investigation] = {}

    def add_batch(self, batch: InvestigationBatch) -> InvestigationBatch:
        for investigation in batch.investigations:
            self._investigations[investigation.investigation_id] = investigation.model_copy(deep=True)
        return batch.model_copy(deep=True)

    def get(self, investigation_id: str) -> Investigation | None:
        investigation = self._investigations.get(investigation_id)
        return investigation.model_copy(deep=True) if investigation is not None else None

    def begin(self, investigation_id: str) -> Investigation:
        investigation = self._require(investigation_id)
        updated = begin_investigation(investigation)
        self._investigations[investigation_id] = updated.model_copy(deep=True)
        return updated.model_copy(deep=True)

    def resolve(self, investigation_id: str, outcome: InvestigationOutcome | None) -> Investigation:
        investigation = self._require(investigation_id)
        updated = resolve_investigation(investigation, outcome)
        self._investigations[investigation_id] = updated.model_copy(deep=True)
        return updated.model_copy(deep=True)

    def _require(self, investigation_id: str) -> Investigation:
        investigation = self.get(investigation_id)
        if investigation is None:
            raise KeyError(f"investigation not found: {investigation_id}")
        return investigation
