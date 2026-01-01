from parser.linux_parser import LinuxAuthParser
from parser.windows_parser import WindowsEventParser
from parser.cloudtrail_parser import CloudTrailParser


from ai_analyzer import AIAnalyzer
from mitre_mapper import MitreMapper
from report_generator import ReportGenerator
import uvicorn

def main():
    linux_file = "sample_logs/auth.log"
    windows_file = "sample_logs/windows_events.jsonl"

    analyzer = AIAnalyzer()
    mapper = MitreMapper()

    # ---- Linux ----
    linux_parser = LinuxAuthParser()
    linux_logs = linux_parser.parse(linux_file)
    linux_findings = analyzer.analyze(linux_logs)
    linux_findings = [mapper.map_to_mitre(f) for f in linux_findings]

    # ---- Windows ----
    win_parser = WindowsEventParser()
    win_logs = win_parser.parse(windows_file)
    win_findings = analyzer.analyze(win_logs)
    win_findings = [mapper.map_to_mitre(f) for f in win_findings]

    all_findings = linux_findings + win_findings

    report = ReportGenerator().generate(all_findings)
    print(report)


if __name__ == "__main__":
    uvicorn.run("src.api:app", host="0.0.0.0", port=80)
