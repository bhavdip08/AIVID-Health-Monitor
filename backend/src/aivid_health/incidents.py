"""Incident episodes projected from the replicated ledger and notification history.

Reading never migrates or rewrites a record. The current ledger, not email
delivery or an old 'open' notification, decides which incidents remain open.
"""
from __future__ import annotations

import hashlib
import time

from .presentation import event_view, server_name

LIFECYCLE = {"open", "escalated", "recovered"}
SEVERITY = {"unknown": 0, "info": 0, "warning": 1, "critical": 2}
PENDING_DELIVERY = {"pending", "retry", "sending", "uncertain"}
LABELS = {"availability": "Server offline", "cpu_percent": "CPU utilization",
          "memory_percent": "Memory utilization", "disk_percent": "Disk utilization",
          "gpu_percent": "GPU utilization", "gpu_memory_percent": "GPU memory",
          "gpu_temperature": "GPU temperature", "sensor_error": "Sensor error"}


def resource_label(metric):
    base, _, resource = metric.partition(":")
    return LABELS.get(base, base.replace("_", " ").capitalize()), resource


def state_id(key, state):
    value = f"{key}/{state.get('opened_at', '')}"
    return "history-" + hashlib.sha256(value.encode()).hexdigest()[:24]


def episode_context(record, node, resource, state):
    """Adopt the existing episode when upgrading or taking over from an old peer."""
    for event in reversed(record["events"]):
        if event.get("node") != node or event.get("metric") != resource:
            continue
        if event.get("kind") == "recovered":
            break
        if event.get("kind") == "open":
            return event.get("incident_id") or "legacy-" + event["id"], event["created_at"]
    return state.get("incident_id") or state_id(node + "/" + resource, state), state.get("opened_at")


def incident_rows(record, config, now=None):
    now = time.time() if now is None else now
    rows, by_id, latest = [], {}, {}

    def new_row(key, identifier, node, metric, opened_at=None, fallback="Unknown server"):
        label, resource = resource_label(metric)
        row = {"id": identifier, "node": node, "node_name": server_name(config, node, fallback),
               "metric": metric, "label": label, "resource": resource, "status": "unknown",
               "severity": "unknown", "opened_at": opened_at, "resolved_at": None,
               "last_changed_at": opened_at, "last_observed": None, "value": None,
               "detail": "", "timeline": [], "history_partial": opened_at is None}
        rows.append(row)
        by_id[key, identifier] = row
        latest[key] = row
        return row

    for event in sorted(record["events"], key=lambda e: e["created_at"]):
        kind = event.get("kind")
        if kind not in LIFECYCLE:
            continue
        node, metric = event["node"], event["metric"]
        key = node + "/" + metric
        identifier = event.get("incident_id")
        row = by_id.get((key, identifier)) if identifier else None
        if row is None and not identifier and kind != "open":
            previous = latest.get(key)
            if previous and previous["resolved_at"] is None:
                row = previous
        if row is None:
            row = new_row(key, identifier or "legacy-" + event["id"], node, metric,
                          event["created_at"] if kind == "open" else event.get("incident_opened_at"),
                          event.get("node_name") or "Unknown server")
            row["history_partial"] = kind != "open"
        latest[key] = row
        if kind == "open":
            row["opened_at"] = event["created_at"]
            row["history_partial"] = False
        if row["opened_at"] is None and event.get("incident_opened_at") is not None:
            row["opened_at"] = event["incident_opened_at"]
        severity = event.get("incident_severity", event.get("severity", "unknown"))
        if SEVERITY.get(severity, 0) > SEVERITY.get(row["severity"], 0):
            row["severity"] = severity
        row["last_changed_at"] = event["created_at"]
        row["detail"] = event.get("detail", "")
        row["value"] = event.get("observed_value")
        row["timeline"].append(event_view(config, event))
        if kind == "recovered":
            row.update(status="closed", resolved_at=event["created_at"])

    for key, state in record["incidents"].items():
        node, _, metric = key.partition("/")
        row = latest.get(key)
        if state.get("active"):
            # A closed historical episode cannot be reopened by a stale ID left
            # on a resource by an older peer. Create the missing current episode.
            if row is None or row["resolved_at"] is not None:
                row = new_row(key, state_id(key, state), node, metric, state.get("opened_at"))
                row["history_partial"] = True
            row.update(status="open", resolved_at=None, severity=state.get("severity", "unknown"),
                       last_observed=state.get("last_observed"), value=state.get("value"))
            if row["opened_at"] is None:
                row["opened_at"] = state.get("opened_at")
            row["last_changed_at"] = row["last_changed_at"] or row["opened_at"]
        elif state.get("resolved_at") is not None:
            if row is None:
                row = new_row(key, state.get("incident_id") or state_id(key, state), node, metric, state.get("opened_at"))
                row.update(severity=state.get("peak_severity", "unknown"), history_partial=True)
            if row["resolved_at"] is None and state["resolved_at"] >= (row["opened_at"] or 0):
                row.update(status="closed", resolved_at=state["resolved_at"], last_changed_at=state["resolved_at"])
                row["history_partial"] = True

    result = []
    for row in rows:
        if row["status"] == "unknown":
            row["history_partial"] = True
        # Completed incident history follows the existing 90-day retention.
        # Unresolved email records may be retained longer in the delivery log.
        if row["status"] == "closed" and row["resolved_at"] < now - 90 * 86400:
            continue
        start, end = row["opened_at"], row["resolved_at"]
        row["duration_seconds"] = max(0, (end if end is not None else now) - start) if start is not None and row["status"] != "unknown" else None
        row["delivery_pending"] = sum(e.get("status") in PENDING_DELIVERY for e in row["timeline"])
        row["latest_delivery"] = row["timeline"][-1]["status"] if row["timeline"] else None
        result.append(row)
    return sorted(result, key=lambda r: (r["last_changed_at"] or 0, r["id"]), reverse=True)


def incident_summary(rows):
    result = {"open": 0, "closed": 0, "unknown": 0, "critical": 0, "warning": 0, "all": len(rows)}
    for row in rows:
        result[row["status"]] += 1
        if row["status"] == "open" and row["severity"] in ("critical", "warning"):
            result[row["severity"]] += 1
    return result


def delivery_summary(events):
    return {"total": len(events), "pending": sum(e.get("status") in PENDING_DELIVERY for e in events),
            "uncertain": sum(e.get("status") == "uncertain" for e in events)}
