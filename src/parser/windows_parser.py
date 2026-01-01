from typing import List, Dict
from .base_parser import BaseParser
import json

class WindowsEventParser(BaseParser):
    """
    Parses Windows Security Event Logs in JSONL format
    and normalizes fields for the AI analyzer.
    """

    def parse(self, file_path: str) -> List[Dict]:
        logs = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                normalized = self._normalize_event(event)
                if normalized:
                    logs.append(normalized)

        return logs

    def parse_from_string(self, content: str):
        temp_path = "temp_win.jsonl"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
        return self.parse(temp_path)

    # ----------------------------
    # Normalization Logic
    # ----------------------------
    def _normalize_event(self, event: Dict) -> Dict:
        """
        Normalize common Windows Security Event fields.
        Works with typical Winlogbeat / EventLog JSON.
        """

        event_id = event.get("EventID") or event.get("event_id")
        if not event_id:
            return None

        # Timestamp (best-effort)
        timestamp = (
            event.get("TimeCreated")
            or event.get("@timestamp")
            or event.get("timestamp")
        )

        # User extraction
        user = (
            event.get("TargetUserName")
            or event.get("SubjectUserName")
            or event.get("UserName")
            or "unknown"
        )

        # IP extraction
        ip = (
            event.get("IpAddress")
            or event.get("SourceIp")
            or event.get("ClientAddress")
            or "unknown"
        )

        # Process extraction
        process = (
            event.get("NewProcessName")
            or event.get("ProcessName")
            or ""
        )

        # Human-readable message
        message = event.get("Message") or event.get("message") or ""

        return {
            "source": "windows",
            "timestamp": timestamp,
            "event_id": int(event_id),
            "user": user,
            "ip": ip,
            "process": process,
            "message": message,
            "raw": event
        }
