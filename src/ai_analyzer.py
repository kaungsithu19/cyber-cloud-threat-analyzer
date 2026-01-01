from typing import List,Dict
from collections import defaultdict
import re

class AIAnalyzer:
    
    """
    Hybrid Threat Analyzer:
    - Deterministic rule-based detection
    - Heuristic pattern analysis
    - AI/LLM integration placeholder
    """
    def __init__(self):
        self.failed_attempts = defaultdict(int)
        self.ip_seen_before = set()

    def analyze(self, logs: List[Dict]) -> List[Dict]:
        aggregated = {}

        for entry in logs:
            result = None

            # Windows (must be first, explicit)
            if entry.get("source") == "windows":
                result = self._analyze_windows(entry)

            # Linux
            elif entry.get("process"):
                result = self._analyze_linux(entry)

            # CloudTrail
            elif "eventName" in entry:
                result = self._analyze_cloudtrail(entry)

            if not result:
                continue

            agg_key = (
                result.get("category", "Unknown"),
                result.get("user", "None"),
                result.get("ip", "None")
            )

            existing = aggregated.get(agg_key)
            if existing:
                sev_order = {"info": 1, "low": 2, "medium": 3, "high": 4}
                if sev_order[result["severity"]] > sev_order[existing["severity"]]:
                    aggregated[agg_key] = result
            else:
                aggregated[agg_key] = result

        return list(aggregated.values())

    def _analyze_linux(self, log: Dict) -> Dict:
        msg = log["message"]

        # ----------------------------
        # SSH FAILED LOGIN (Brute Force)
        # ----------------------------
        if "Failed password" in msg:
            ip = self._extract_ip(msg)
            user = self._extract_username(msg)
            key = f"{user}:{ip}"

            self.failed_attempts[key] += 1
            count = self.failed_attempts[key]

            if count > 5:
                severity = "high"
            elif count >= 3:
                severity = "medium"
            else:
                severity = "low"

            return {
                "log": log,
                "severity": severity,
                "description": f"Multiple failed SSH login attempts ({count})",
                "category": "Brute Force",
                "ip": ip,
                "user": user
            }

        # --------------------------------
        # SSH SUCCESSFUL PASSWORD LOGIN
        # --------------------------------
        if "Accepted password" in msg:
            ip = self._extract_ip(msg)
            user = self._extract_username(msg)

            severity = "high" if ip not in self.ip_seen_before else "info"
            self.ip_seen_before.add(ip)

            return {
                "log": log,
                "severity": severity,
                "description": f"Successful SSH login from new IP address {ip}",
                "category": "Suspicious Login",
                "ip": ip,
                "user": user
            }

        # --------------------------------
        # SSH SUCCESSFUL PUBLIC KEY LOGIN
        # --------------------------------
        if "Authentication succeeded (publickey)" in msg:
            ip = self._extract_ip(msg)
            user = self._extract_username(msg)

            return {
                "log": log,
                "severity": "info",
                "description": "SSH login using public key authentication",
                "category": "Lateral Movement",
                "ip": ip,
                "user": user
            }

        # ----------------------------
        # SUDO PRIVILEGE ESCALATION
        # ----------------------------
        if log.get("process") == "sudo" and "COMMAND=" in msg:
            user = self._extract_sudo_user(msg)

            return {
                "log": log,
                "severity": "medium",
                "description": "Privilege escalation via sudo command execution",
                "category": "Privilege Escalation",
                "user": user
            }
        
        # ----------------------------
        # CRON PERSISTENCE DETECTION
        # ----------------------------
        if "CRON" in msg and "CMD=" in msg:
            severity = "high" if "/tmp/" in msg else "medium"

            return {
                "log": log,
                "severity": severity,
                "description": "Scheduled task executed via cron",
                "category": "Persistence"
            }

        # ----------------------------
        # CREDENTIAL ACCESS (/etc/shadow)
        # ----------------------------
        if "/etc/shadow" in msg:
            return {
                "log": log,
                "severity": "high",
                "description": "Access to sensitive credential file /etc/shadow",
                "category": "Credential Access"
            }

        return None


    
    #Helpers

    def _extract_ip(self, msg:str) -> str:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", msg)
        return m.group(1) if m else "unknown"
    
    def _extract_username(self, msg:str) -> str:
        m = re.search(r"for (\w+)", msg)
        return m.group(1) if m else "unknown"
    
    def _extract_sudo_user(self, msg: str) -> str:
        m = re.search(r"^\s*(\w+)\s*:", msg)
        return m.group(1) if m else "unknown"


    
    # ----------------------------
    # Windows Event Analysis
    # ----------------------------

    def _analyze_windows(self, log: Dict) -> Dict:
        event_id = log.get("event_id")   # ✅ normalized field
        user = log.get("user", "unknown")
        ip = log.get("ip", "unknown")
        process = log.get("process", "")
        msg = log.get("message", "")

        # ----------------------------
        # FAILED LOGIN (4625)
        # ----------------------------
        if event_id == 4625:
            return {
                "log": log,
                "severity": "medium",
                "description": "Failed Windows login attempt",
                "category": "Brute Force",
                "user": user,
                "ip": ip
            }

        # ----------------------------
        # SUCCESSFUL LOGIN (4624)
        # ----------------------------
        if event_id == 4624:
            return {
                "log": log,
                "severity": "info",
                "description": "Successful Windows login",
                "category": "Suspicious Login",
                "user": user,
                "ip": ip
            }

        # ----------------------------
        # PRIVILEGED LOGON (4672)
        # ----------------------------
        if event_id == 4672:
            return {
                "log": log,
                "severity": "high",
                "description": "Privileged account logged on",
                "category": "Privilege Escalation",
                "user": user,
                "ip": ip
            }

        # ----------------------------
        # PROCESS CREATION (4688)
        # ----------------------------
        if event_id == 4688:
            proc_lower = process.lower()

            severity = "low"
            if "powershell" in proc_lower or "cmd.exe" in proc_lower:
                severity = "high"
            elif "temp" in proc_lower:
                severity = "medium"

            return {
                "log": log,
                "severity": severity,
                "description": f"Process created: {process}",
                "category": "Process Creation",
                "user": user,
                "ip": ip
            }

        return None


    # ----------------------------
    # CloudTrail Analysis
    # ----------------------------

    def _analyze_cloudtrail(self, log: Dict) -> Dict:
        event_name = log.get("eventName", "")
        event_time = log.get("eventTime")
        source_ip = log.get("sourceIPAddress", "unknown")

        # User extraction (safe)
        user_identity = log.get("userIdentity", {})
        user = (
            user_identity.get("userName")
            or user_identity.get("arn")
            or user_identity.get("principalId")
            or "unknown"
        )

        error_code = log.get("errorCode", "")
        error_message = log.get("errorMessage", "")

        # ----------------------------
        # UNAUTHORIZED API CALLS
        # ----------------------------
        if "Unauthorized" in error_code or "Unauthorized" in error_message:
            return {
                "log": log,
                "severity": "high",
                "description": f"Unauthorized AWS API call: {event_name}",
                "category": "IAM Misuse",
                "user": user,
                "ip": source_ip,
                "timestamp": event_time
            }

        # ----------------------------
        # FAILED CONSOLE LOGIN
        # ----------------------------
        if event_name == "ConsoleLogin" and error_message:
            return {
                "log": log,
                "severity": "medium",
                "description": f"Failed AWS console login: {error_message}",
                "category": "Suspicious Login",
                "user": user,
                "ip": source_ip,
                "timestamp": event_time
            }

        # ----------------------------
        # IAM PRIVILEGE ESCALATION
        # ----------------------------
        if event_name.startswith(("Put", "Attach", "Create")) and "Policy" in event_name:
            return {
                "log": log,
                "severity": "high",
                "description": f"IAM policy modification: {event_name}",
                "category": "Privilege Escalation",
                "user": user,
                "ip": source_ip,
                "timestamp": event_time
            }

        # ----------------------------
        # SENSITIVE READ ACTIONS
        # ----------------------------
        if event_name.startswith(("Get", "Describe", "List")):
            return {
                "log": log,
                "severity": "low",
                "description": f"Sensitive AWS API read action: {event_name}",
                "category": "Reconnaissance",
                "user": user,
                "ip": source_ip,
                "timestamp": event_time
            }

        return None
