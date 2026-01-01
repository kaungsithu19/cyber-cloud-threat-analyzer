from fastapi import FastAPI, UploadFile, File
from src.dashboard import router as dashboard_router

from src.ai_analyzer import AIAnalyzer
from src.mitre_mapper import MitreMapper

from src.parser.linux_parser import LinuxAuthParser
from src.parser.windows_parser import WindowsEventParser
from src.parser.cloudtrail_parser import CloudTrailParser

from fastapi.staticfiles import StaticFiles


app = FastAPI(
    title="Cyber Cloud Threat Analyzer",
    description="AI-powered log analysis with MITRE ATT&CK mapping",
    version="1.0"
)

@app.get("/health")
def health_check():
    return {"status": "running"}

@app.post("/analyze/linux")
async def analyze_linux_log(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8")

    parser = LinuxAuthParser()
    logs = parser.parse_from_string(content)

    analyzer = AIAnalyzer()
    findings = analyzer.analyze(logs)

    mapper = MitreMapper()
    mapped = [mapper.map_to_mitre(f) for f in findings]

    return {"results": mapped}

@app.post("/analyze/windows")
async def analyze_windows_log(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8")

    parser = WindowsEventParser()
    logs = parser.parse_from_string(content)

    analyzer = AIAnalyzer()
    findings = analyzer.analyze(logs)

    mapper = MitreMapper()
    mapped = [mapper.map_to_mitre(f) for f in findings]

    return {"results": mapped}

@app.post("/analyze/cloudtrail")
async def analyze_cloudtrail_log(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8")

    parser = CloudTrailParser()
    logs = parser.parse_from_string_json(content)

    analyzer = AIAnalyzer()
    findings = analyzer.analyze(logs)

    mapper = MitreMapper()
    mapped = [mapper.map_to_mitre(f) for f in findings]

    return {"results": mapped}

app.mount(
    "/static",
    StaticFiles(directory="src/static"),
    name="static"
)

app.include_router(dashboard_router)

