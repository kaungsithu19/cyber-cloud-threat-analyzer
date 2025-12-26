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
        results = []
        for entry in logs:
            result = {
                "log": entry,
                "severity" : "info",
                "description" : "Placeholder analysis"
            }
        
            if "message" in entry:
                linux_result = self._analyze_linux(entry)
                if linux_result:
                    results.append(linux_result)
                    continue

            if "EventID" in entry:
                windows_result = self.__analyze_windows(entry)
                if windows_result:
                    results.append(windows_result)
                    continue

            if "eventName" in entry:
                cloud_result = self._analyze_cloudtrail(entry)
                if cloud_result:
                    results.append(cloud_result)
                    continue
            results.append(result)
        return results
    # ----------------------------
    # Linux Log Analysis
    # ----------------------------   \
    # 
    def _analyze_linux(self, log:Dict) -> Dict:
        msg = log["message"]

        #Failed SSH login
        if "Failed password" in msg:
            ip = self._extract_ip(msg)
            user = self._extract_username(msg)
            key = f"{user}:{ip}"    
            self.failed_attempts[key] += 1

            count = self.failed_attempts[key]
            if count > 5:
                severity = "high"
            elif count >=3:
                severity = "medium" 
            else:
                severity ="low"

            return {
                "log" : log,
                "severity": severity,
                "description" : f"Multiple failed login attempts ({count})",
                "category" : "Brute Force",
                "ip" : ip,
                "user" : user
            }
        
        # Successful login from a new IP
        if "Accepted password" in msg:
            ip = self._extract_ip(msg)

            severity = "high" if ip not in self.ip_seen_before else "info"
            self.ip_seen_before.add(ip)

            return {
                "log": log,
                "severrity": severity,
                "description" : "Successful login from new Ip address",
                "category" : "Suspicious login",
                "ip" : ip
            }

        if "sudo" in msg and "COMMAND=" in msg:
            return {
                "log" : log,
                "severity" : "medium",
                "description" : "Privilege escalation attempt (sudo usage)",
                "category" : "Privilege Escation",
            }
        return None
    
    #Helpers

    def _extract_ip(self, msg:str) -> str:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", msg)
        return m.group(1) if m else "unknown"
    
    def _extract_username(self, msg:str) -> str:
        m = re.search(r"for (\w+)", msg)
        return m.group(1) if m else "unknown"
    
    # ----------------------------
    # Windows Event Analysis
    # ----------------------------

    def _analyze_windows(self, log: Dict) -> Dict:
        event_id = log.get("EventID")

        #Failed Login
        if event_id == 4625:
            return {
                "log" : log,
                "severity" : "info",
                "description": "Successful Windows Login (Event 4624)"

            }
        
        #Process created
        if event_id == 4688:
            process =log.get("NewProcessName", "")

            severity = "high" if "powershell" in process.lower() else "low"

            return {
                "log" : log,
                "severity" : severity,
                "description" : f"Process created: {process}",
                "category": "Process Creation"
            }
        return None

    # ----------------------------
    # CloudTrail Analysis
    # ----------------------------

    def _analyze_cloudtrail(self, log: Dict) -> Dict:
        event = log.get("eventName", "")

        #Unauthorized API call
        if event == "UnauthorizedOperation":
            return {
                "log": log,
                "severity" : "high",
                "description" : "Unauthorized API call detected",
                "category" : "IAM Misuse" 
            }
        
        # IAM policy changes

        if event in ["PutUserPoicy", "AttcahRolePolicy", "CreatePolicyVersion"]:
            return {
                "log" : log,
                "severity" : "high",
                "description" : f"IAM policy modification: {event}",
                "category": "Privilege Escation"

            }
        
            #Console login failures
            if event == "consoleLogin" and log.get("errorMessage"):
                return {
                    "log": log,
                    "severity" : "medium",
                    "description" : f"Failed AWS console login: {log.get('errorMessage')}",

                }
            return None