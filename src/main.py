from parser.linux_parser import LinuxAuthParser
from parser.windows_parser import WindowsEventParser
from parser.cloudtrail_parser import CloudTrailParser


from ai_analyzer import AIAnalyzer
from mitre_mapper import MitreMapper
from report_generator import ReportGenerator
import uvicorn

def main():
    
    linux_file = "sample_logs/auth.log"
    cloudtrail_file = "sample_logs/cloudtrail.json"
    windows_file = "sample_logs/windows_events.jsonl"

    # 1. Linux logs
    parser = LinuxAuthParser()
    logs = parser.parse(linux_file)

    # 2. Analyze
    analyzer = AIAnalyzer()
    findings = analyzer.analyze(logs)

    # 3. MITRE mapping
    mapper = MitreMapper()
    findings = [mapper.map_to_mitre(f) for f in findings]

    # 4. Reporting
    report = ReportGenerator().generate(findings)
    print(report)

import uvicorn

if __name__ == "__main__":
    uvicorn.run("src.api:app", host="0.0.0.0", port=80)
