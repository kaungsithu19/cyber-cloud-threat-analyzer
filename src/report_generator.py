from typing import List, Dict

class ReportGenerator:
    def generate(self, findings: List[Dict]) -> str:
        report_lines = ["=== Incident Report (Preview) ==="]
        for item in findings:
            report_lines.append(f"- Severity: {item['severity']}")
            report_lines.append(f"  MITRE: {item.get('mitre_id')} - {item.get('mitre_name')}")
            report_lines.append(f"  Raw log: {item['log']}")
            report_lines.append("")

        return "\n".join(report_lines)
    