from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from app.core.config import settings

class BruteForceDetector:
    """Stateful sliding-window brute-force attack detector (FR-12)."""

    def __init__(self, window_seconds: int = 300, max_failures: int = 5):
        self.window_seconds = window_seconds
        self.max_failures = max_failures
        # Map: entity (ip or username) -> list of failure timestamps
        self.failure_history: Dict[str, List[datetime]] = defaultdict(list)

    def record_failure(self, entity_id: str, timestamp: Optional[datetime] = None) -> Tuple[bool, int, str]:
        """Record an authentication failure and check threshold."""
        now = timestamp or datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Filter out old attempts
        self.failure_history[entity_id] = [
            t for t in self.failure_history[entity_id] if t > cutoff
        ]
        self.failure_history[entity_id].append(now)

        count = len(self.failure_history[entity_id])
        is_attack = count >= self.max_failures
        reason = f"Detected {count} authentication failures within {self.window_seconds}s" if is_attack else ""
        return is_attack, count, reason

class PortScanDetector:
    """Stateful sliding-window multi-port reconnaissance detector (FR-13)."""

    def __init__(self, window_seconds: int = 60, port_threshold: int = 10):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        # Map: source_ip -> list of (timestamp, dest_port)
        self.scan_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)

    def record_connection(self, source_ip: str, dest_port: int, timestamp: Optional[datetime] = None) -> Tuple[bool, int, str]:
        """Track distinct ports probed from a source IP."""
        now = timestamp or datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Clean history
        self.scan_history[source_ip] = [
            (t, p) for (t, p) in self.scan_history[source_ip] if t > cutoff
        ]
        self.scan_history[source_ip].append((now, dest_port))

        # Count unique ports contacted
        unique_ports: Set[int] = {p for (_, p) in self.scan_history[source_ip]}
        port_count = len(unique_ports)

        is_scan = port_count >= self.port_threshold
        reason = f"Probed {port_count} distinct destination ports from {source_ip} within {self.window_seconds}s" if is_scan else ""
        return is_scan, port_count, reason

brute_force_detector = BruteForceDetector(
    window_seconds=settings.BRUTE_FORCE_WINDOW_SECONDS,
    max_failures=settings.BRUTE_FORCE_MAX_ATTEMPTS
)
port_scan_detector = PortScanDetector(
    window_seconds=settings.PORT_SCAN_WINDOW_SECONDS,
    port_threshold=settings.PORT_SCAN_PORT_THRESHOLD
)
