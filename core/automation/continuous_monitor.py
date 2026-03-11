#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  👁️ SIREN CONTINUOUS MONITOR — Persistent Surveillance Engine  👁️            ██
██                                                                                ██
██  Monitoração contínua de alvos com detecção de mudanças e alertas.           ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Change detection — hash-based diffing para content, headers, DNS        ██
██    • Scheduled scanning — cron-like scheduling sem dependências              ██
██    • Alert system — multi-level alerts com callback hooks                     ██
██    • Asset tracking — inventory vivo com auto-discovery                       ██
██    • Certificate monitoring — expiry, chain, revocation checks               ██
██    • DNS monitoring — record changes, zone transfer detection                ██
██    • Response fingerprint — behavioral drift detection                        ██
██                                                                                ██
██  "SIREN nunca dorme — e nenhuma mudança escapa."                             ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.automation.continuous_monitor")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class MonitorType(Enum):
    HTTP_CONTENT = auto()
    HTTP_HEADERS = auto()
    DNS_RECORDS = auto()
    TLS_CERTIFICATE = auto()
    PORT_STATUS = auto()
    RESPONSE_TIME = auto()
    TECHNOLOGY_STACK = auto()
    CUSTOM = auto()


class AlertSeverity(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ChangeType(Enum):
    ADDED = auto()
    REMOVED = auto()
    MODIFIED = auto()
    DEGRADED = auto()
    RECOVERED = auto()


class MonitorStatus(Enum):
    ACTIVE = auto()
    PAUSED = auto()
    ERROR = auto()
    DISABLED = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ChangeEvent:
    """Represents a detected change."""
    id: str = ""
    monitor_type: MonitorType = MonitorType.CUSTOM
    change_type: ChangeType = ChangeType.MODIFIED
    target: str = ""
    field_name: str = ""
    old_value: str = ""
    new_value: str = ""
    timestamp: float = field(default_factory=time.time)
    severity: AlertSeverity = AlertSeverity.INFO

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "monitor_type": self.monitor_type.name,
            "change_type": self.change_type.name,
            "target": self.target,
            "field": self.field_name,
            "old_value": self.old_value[:200],
            "new_value": self.new_value[:200],
            "timestamp": self.timestamp,
            "severity": self.severity.name,
        }


@dataclass
class Alert:
    """An alert generated from change detection."""
    id: str = ""
    severity: AlertSeverity = AlertSeverity.INFO
    title: str = ""
    description: str = ""
    target: str = ""
    change_events: List[ChangeEvent] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "events": len(self.change_events),
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }


@dataclass
class MonitorTarget:
    """A target being monitored."""
    id: str = ""
    target: str = ""
    monitor_types: List[MonitorType] = field(default_factory=list)
    interval_s: float = 3600.0  # Default: check every hour
    status: MonitorStatus = MonitorStatus.ACTIVE
    last_check: float = 0.0
    next_check: float = 0.0
    check_count: int = 0
    error_count: int = 0
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "types": [t.name for t in self.monitor_types],
            "interval_s": self.interval_s,
            "status": self.status.name,
            "check_count": self.check_count,
            "error_count": self.error_count,
        }


@dataclass
class Snapshot:
    """Point-in-time capture of target state."""
    target: str = ""
    monitor_type: MonitorType = MonitorType.CUSTOM
    timestamp: float = field(default_factory=time.time)
    data_hash: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "type": self.monitor_type.name,
            "timestamp": self.timestamp,
            "hash": self.data_hash,
        }


# ════════════════════════════════════════════════════════════════════════════════
# CONTENT DIFFER — Hash-based change detection
# ════════════════════════════════════════════════════════════════════════════════

class ContentDiffer:
    """Detects changes between snapshots via hashing and field-level diff."""

    @staticmethod
    def compute_hash(data: Any) -> str:
        """Compute stable hash of any serializable data."""
        serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def diff_snapshots(self, old: Snapshot, new: Snapshot) -> List[ChangeEvent]:
        """Compare two snapshots and detect changes."""
        if old.data_hash == new.data_hash:
            return []

        changes: List[ChangeEvent] = []

        old_keys = set(old.data.keys())
        new_keys = set(new.data.keys())

        # Added fields
        for key in new_keys - old_keys:
            changes.append(ChangeEvent(
                monitor_type=new.monitor_type,
                change_type=ChangeType.ADDED,
                target=new.target,
                field_name=key,
                new_value=str(new.data[key]),
            ))

        # Removed fields
        for key in old_keys - new_keys:
            changes.append(ChangeEvent(
                monitor_type=old.monitor_type,
                change_type=ChangeType.REMOVED,
                target=old.target,
                field_name=key,
                old_value=str(old.data[key]),
            ))

        # Modified fields
        for key in old_keys & new_keys:
            old_val = str(old.data[key])
            new_val = str(new.data[key])
            if old_val != new_val:
                changes.append(ChangeEvent(
                    monitor_type=new.monitor_type,
                    change_type=ChangeType.MODIFIED,
                    target=new.target,
                    field_name=key,
                    old_value=old_val,
                    new_value=new_val,
                ))

        return changes


# ════════════════════════════════════════════════════════════════════════════════
# ALERT ENGINE — Severity calculation & alert generation
# ════════════════════════════════════════════════════════════════════════════════

class AlertEngine:
    """Generates alerts from detected changes with severity classification."""

    # Fields that indicate security-relevant changes
    CRITICAL_FIELDS: Set[str] = {
        "certificate_expiry", "certificate_issuer", "certificate_chain",
        "open_ports", "tls_version", "cipher_suite",
    }

    HIGH_FIELDS: Set[str] = {
        "server_header", "x_powered_by", "technology_stack",
        "dns_records", "nameservers", "mx_records",
        "security_headers",
    }

    def __init__(self) -> None:
        self._callbacks: List[Callable[[Alert], None]] = []
        self._lock = threading.RLock()
        self._alert_count = 0

    def register_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a callback for new alerts."""
        with self._lock:
            self._callbacks.append(callback)

    def generate_alert(self, target: str, changes: List[ChangeEvent]) -> Optional[Alert]:
        """Generate an alert from change events."""
        if not changes:
            return None

        severity = self._compute_severity(changes)
        with self._lock:
            self._alert_count += 1
            alert_id = f"ALERT-{self._alert_count:06d}"

        alert = Alert(
            id=alert_id,
            severity=severity,
            title=self._generate_title(target, changes),
            description=self._generate_description(changes),
            target=target,
            change_events=changes,
        )

        self._dispatch_alert(alert)
        return alert

    def _compute_severity(self, changes: List[ChangeEvent]) -> AlertSeverity:
        """Compute alert severity from change events."""
        max_sev = AlertSeverity.INFO

        for change in changes:
            if change.field_name in self.CRITICAL_FIELDS:
                return AlertSeverity.CRITICAL
            elif change.field_name in self.HIGH_FIELDS:
                max_sev = max(max_sev, AlertSeverity.HIGH, key=lambda x: x.value)
            elif change.change_type == ChangeType.REMOVED:
                max_sev = max(max_sev, AlertSeverity.MEDIUM, key=lambda x: x.value)
            else:
                max_sev = max(max_sev, AlertSeverity.LOW, key=lambda x: x.value)

        return max_sev

    @staticmethod
    def _generate_title(target: str, changes: List[ChangeEvent]) -> str:
        types = {c.change_type.name for c in changes}
        return f"[{','.join(types)}] {len(changes)} change(s) on {target}"

    @staticmethod
    def _generate_description(changes: List[ChangeEvent]) -> str:
        lines = []
        for c in changes[:10]:  # Cap description
            lines.append(f"  {c.change_type.name}: {c.field_name}")
        if len(changes) > 10:
            lines.append(f"  ... and {len(changes) - 10} more")
        return "\n".join(lines)

    def _dispatch_alert(self, alert: Alert) -> None:
        with self._lock:
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error("Alert callback error: %s", e)


# ════════════════════════════════════════════════════════════════════════════════
# SCHEDULE ENGINE — Cron-like scheduling WITHOUT external deps
# ════════════════════════════════════════════════════════════════════════════════

class ScheduleEngine:
    """Simple scheduling engine for monitor checks."""

    def get_due_targets(self, targets: List[MonitorTarget], now: float = 0.0) -> List[MonitorTarget]:
        """Return targets that are due for a check."""
        now = now or time.time()
        due = []
        for t in targets:
            if t.status != MonitorStatus.ACTIVE:
                continue
            if now >= t.next_check:
                due.append(t)
        # Sort by priority: longest overdue first
        due.sort(key=lambda x: x.next_check)
        return due

    @staticmethod
    def update_next_check(target: MonitorTarget) -> None:
        """Update next check time after a check."""
        target.last_check = time.time()
        target.check_count += 1

        # Exponential backoff on errors
        if target.error_count > 3:
            backoff = min(target.interval_s * (2 ** min(target.error_count - 3, 5)),
                          86400.0)  # Max 24h
            target.next_check = target.last_check + backoff
        else:
            target.next_check = target.last_check + target.interval_s


# ════════════════════════════════════════════════════════════════════════════════
# HTTP MONITOR — HTTP-specific monitoring
# ════════════════════════════════════════════════════════════════════════════════

class HTTPMonitor:
    """Monitor HTTP responses for changes."""

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    def capture_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Capture HTTP response header snapshot."""
        data: Dict[str, Any] = {}

        # Server info
        data["server_header"] = headers.get("server", "")
        data["x_powered_by"] = headers.get("x-powered-by", "")

        # Security headers
        for hdr in self.SECURITY_HEADERS:
            data[f"header_{hdr}"] = headers.get(hdr, "")

        # Cookie flags
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            data["cookie_secure"] = "secure" in set_cookie.lower()
            data["cookie_httponly"] = "httponly" in set_cookie.lower()
            data["cookie_samesite"] = "samesite" in set_cookie.lower()

        return data

    def capture_content(self, body: str) -> Dict[str, Any]:
        """Capture content snapshot."""
        return {
            "content_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
            "content_length": len(body),
            "has_forms": "<form" in body.lower(),
            "has_scripts": "<script" in body.lower(),
            "has_iframes": "<iframe" in body.lower(),
            "external_links": body.lower().count('href="http'),
        }


# ════════════════════════════════════════════════════════════════════════════════
# DNS MONITOR — DNS record monitoring
# ════════════════════════════════════════════════════════════════════════════════

class DNSMonitor:
    """Monitor DNS record changes."""

    def capture_records(self, records: Dict[str, List[str]]) -> Dict[str, Any]:
        """Capture DNS record snapshot."""
        data: Dict[str, Any] = {}
        for rtype, values in records.items():
            data[f"dns_{rtype}"] = ",".join(sorted(values))
        return data


# ════════════════════════════════════════════════════════════════════════════════
# TLS MONITOR — Certificate monitoring
# ════════════════════════════════════════════════════════════════════════════════

class TLSMonitor:
    """Monitor TLS certificate state."""

    def capture_cert(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Capture certificate snapshot."""
        return {
            "certificate_subject": cert_info.get("subject", ""),
            "certificate_issuer": cert_info.get("issuer", ""),
            "certificate_expiry": cert_info.get("not_after", ""),
            "certificate_serial": cert_info.get("serial_number", ""),
            "certificate_chain": str(cert_info.get("chain_length", 0)),
            "tls_version": cert_info.get("tls_version", ""),
            "cipher_suite": cert_info.get("cipher_suite", ""),
        }

    def check_expiry(self, not_after_ts: float) -> Optional[ChangeEvent]:
        """Check if certificate is near expiry."""
        now = time.time()
        days_left = (not_after_ts - now) / 86400.0

        if days_left < 0:
            return ChangeEvent(
                monitor_type=MonitorType.TLS_CERTIFICATE,
                change_type=ChangeType.DEGRADED,
                field_name="certificate_expiry",
                new_value=f"EXPIRED ({abs(days_left):.0f} days ago)",
                severity=AlertSeverity.CRITICAL,
            )
        elif days_left < 7:
            return ChangeEvent(
                monitor_type=MonitorType.TLS_CERTIFICATE,
                change_type=ChangeType.DEGRADED,
                field_name="certificate_expiry",
                new_value=f"Expires in {days_left:.0f} days",
                severity=AlertSeverity.CRITICAL,
            )
        elif days_left < 30:
            return ChangeEvent(
                monitor_type=MonitorType.TLS_CERTIFICATE,
                change_type=ChangeType.DEGRADED,
                field_name="certificate_expiry",
                new_value=f"Expires in {days_left:.0f} days",
                severity=AlertSeverity.HIGH,
            )
        return None


# ════════════════════════════════════════════════════════════════════════════════
# SIREN CONTINUOUS MONITOR — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenContinuousMonitor:
    """
    Main continuous monitoring engine.

    Manages monitored targets, detects changes against baselines,
    generates alerts, and maintains monitoring schedules.

    Usage:
        monitor = SirenContinuousMonitor()

        # Add target
        target = monitor.add_target("https://example.com",
            types=[MonitorType.HTTP_CONTENT, MonitorType.TLS_CERTIFICATE])

        # Record baseline
        monitor.record_snapshot(target.id, MonitorType.HTTP_CONTENT, {"content": "..."})

        # Later: check for changes
        changes = monitor.check_target(target.id, MonitorType.HTTP_CONTENT, {"content": "new..."})
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: Dict[str, MonitorTarget] = {}
        self._baselines: Dict[str, Dict[MonitorType, Snapshot]] = {}  # target_id -> type -> snapshot
        self._history: Dict[str, List[ChangeEvent]] = defaultdict(list)
        self._alerts: List[Alert] = []
        self._differ = ContentDiffer()
        self._alert_engine = AlertEngine()
        self._scheduler = ScheduleEngine()
        self._http_monitor = HTTPMonitor()
        self._dns_monitor = DNSMonitor()
        self._tls_monitor = TLSMonitor()
        self._target_counter = 0
        logger.info("SirenContinuousMonitor initialized")

    def add_target(self, target: str, types: Optional[List[MonitorType]] = None,
                   interval_s: float = 3600.0) -> MonitorTarget:
        """Add a target for monitoring."""
        with self._lock:
            self._target_counter += 1
            mt = MonitorTarget(
                id=f"MON-{self._target_counter:06d}",
                target=target,
                monitor_types=types or [MonitorType.HTTP_CONTENT],
                interval_s=interval_s,
                next_check=time.time(),
            )
            self._targets[mt.id] = mt
            self._baselines[mt.id] = {}
            return mt

    def remove_target(self, target_id: str) -> bool:
        with self._lock:
            if target_id in self._targets:
                del self._targets[target_id]
                self._baselines.pop(target_id, None)
                return True
            return False

    def record_snapshot(self, target_id: str, monitor_type: MonitorType,
                         data: Dict[str, Any]) -> Snapshot:
        """Record a baseline snapshot."""
        snapshot = Snapshot(
            target=self._targets.get(target_id, MonitorTarget()).target,
            monitor_type=monitor_type,
            data=data,
            data_hash=self._differ.compute_hash(data),
        )
        with self._lock:
            if target_id not in self._baselines:
                self._baselines[target_id] = {}
            self._baselines[target_id][monitor_type] = snapshot
        return snapshot

    def check_target(self, target_id: str, monitor_type: MonitorType,
                      current_data: Dict[str, Any]) -> List[ChangeEvent]:
        """Check a target against its baseline, detect changes."""
        with self._lock:
            baseline = self._baselines.get(target_id, {}).get(monitor_type)

        if not baseline:
            # First check — record baseline
            self.record_snapshot(target_id, monitor_type, current_data)
            return []

        current_snapshot = Snapshot(
            target=baseline.target,
            monitor_type=monitor_type,
            data=current_data,
            data_hash=self._differ.compute_hash(current_data),
        )

        changes = self._differ.diff_snapshots(baseline, current_snapshot)

        if changes:
            with self._lock:
                self._history[target_id].extend(changes)
                # Update baseline
                self._baselines[target_id][monitor_type] = current_snapshot

            # Generate alert
            target = self._targets.get(target_id)
            if target:
                alert = self._alert_engine.generate_alert(target.target, changes)
                if alert:
                    with self._lock:
                        self._alerts.append(alert)

        return changes

    def get_due_checks(self) -> List[MonitorTarget]:
        """Get targets due for checking."""
        with self._lock:
            return self._scheduler.get_due_targets(list(self._targets.values()))

    def mark_checked(self, target_id: str, error: str = "") -> None:
        """Mark a target as checked."""
        with self._lock:
            target = self._targets.get(target_id)
            if target:
                if error:
                    target.error_count += 1
                    target.last_error = error
                else:
                    target.error_count = 0
                self._scheduler.update_next_check(target)

    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        self._alert_engine.register_callback(callback)

    def get_alerts(self, severity_min: AlertSeverity = AlertSeverity.INFO,
                   unacknowledged_only: bool = False) -> List[Alert]:
        with self._lock:
            alerts = list(self._alerts)
        filtered = [a for a in alerts if a.severity.value >= severity_min.value]
        if unacknowledged_only:
            filtered = [a for a in filtered if not a.acknowledged]
        return filtered

    def get_change_history(self, target_id: str, limit: int = 100) -> List[ChangeEvent]:
        with self._lock:
            history = self._history.get(target_id, [])
            return history[-limit:]

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "targets_total": len(self._targets),
                "targets_active": sum(1 for t in self._targets.values() if t.status == MonitorStatus.ACTIVE),
                "targets_error": sum(1 for t in self._targets.values() if t.status == MonitorStatus.ERROR),
                "total_alerts": len(self._alerts),
                "unacked_alerts": sum(1 for a in self._alerts if not a.acknowledged),
                "total_changes": sum(len(h) for h in self._history.values()),
                "targets": [t.to_dict() for t in self._targets.values()],
            }
