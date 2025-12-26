from typing import Dict

class MitreMapper:
    MITRE_REGISTRY = {
        "Brute Force" : {
            "technique_id" : "T1110",
            "technique_name" : "Brute Force"
        },
        "Suspicious Login": {
            "technique_id" : "T1078",
            "technique_name" : "Valid Accounts"
        },
        "Privilege Escation": {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escation"
        },
        "Process Creation": {
            "technique_id": "T1059",
            "technique_name": "Command and Scription Interpreter"
        },
        "IAM Misuse": {
            "technique_id": "T1484",
            "technique_name": "Domain Policy Modification"
        },
        "Cloud Unauthorized": {
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storag Object"
        },
        "Credential Acess": {
            "technique_id": "T1003",
            "technique_name": "Credential Dumping"
        },
        "Lateral Movement": {
            "technique_id": "T1021",
            "technique_name": "Remote Servies"
        }
    }

    def map_to_mitre(self, analysis: Dict) -> Dict:
        category = analysis.get("category", "Unknown")

        mitre = self.MITRE_REGISTRY.get(category, None)

        if mitre:
            analysis["mitre_id"] = mitre["technique_id"]
            analysis["mitre_name"] = mitre["technique_name"]
        else:
            analysis["mitre_id"] = "T0000"
            analysis["mitre_name"] = "Unknown Technique"
        
        return analysis