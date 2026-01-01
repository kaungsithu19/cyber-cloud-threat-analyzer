from typing import Dict

class MitreMapper:
    """
    Maps detection categories to real MITRE ATT&CK techniques.
    All technique IDs and names have been corrected and standardized.
    """

    MITRE_REGISTRY = {
        "Brute Force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force"
        },
        "Suspicious Login": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts"
        },
        "Privilege Escalation": {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation"
        },
        "Process Creation": {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter"
        },
        "IAM Misuse": {
            "technique_id": "T1484",
            "technique_name": "Domain Policy Modification"
        },
        "Cloud Unauthorized": {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage Object"
        },
        "Credential Access": {
            "technique_id": "T1003",
            "technique_name": "Credential Dumping"
        },
        "Lateral Movement": {
            "technique_id": "T1021",
            "technique_name": "Remote Services"
        },
        "Persistence": {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job"
        },
        "Reconnaissance": {
            "technique_id": "T1595",
            "technique_name": "Active Scanning"
        },
        "IAM Misuse": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts"
        }


    }

    def map_to_mitre(self, analysis: Dict) -> Dict:
        """
        Attach MITRE metadata to a detection result.
        Falls back to 'Unknown Technique' if not mapped.
        """

        category = analysis.get("category", "Unknown")

        mitre = self.MITRE_REGISTRY.get(category)

        if mitre:
            analysis["mitre_id"] = mitre["technique_id"]
            analysis["mitre_name"] = mitre["technique_name"]
        else:
            analysis["mitre_id"] = "T0000"
            analysis["mitre_name"] = "Unknown Technique"

        return analysis
