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
    
def add_ai_recommendations(self, ai_data: dict) -> str:
    section = "\n=== AI SECURITY RECOMMENDATIONS ===\n"
    section += f"Risk Summary:\n{ai_data.get('risk_summary')}\n\n"

    section += "Immediate Actions:\n"
    for a in ai_data.get("immediate_actions", []):
        section += f"- {a}\n"

    section += "\nPreventive Controls:\n"
    for p in ai_data.get("preventive_controls", []):
        section += f"- {p}\n"

    section += f"\nPriority: {ai_data.get('priority')}\n"
    return section

    