from fastapi import APIRouter, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from collections import Counter, defaultdict
from datetime import datetime

from src.ai_analyzer import AIAnalyzer
from src.mitre_mapper import MitreMapper
from src.parser.linux_parser import LinuxAuthParser
from src.parser.windows_parser import WindowsEventParser
from src.parser.cloudtrail_parser import CloudTrailParser

templates = Jinja2Templates(directory="src/templates")
router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


def _severity_rank(sev: str) -> int:
    order = {"info": 1, "low": 2, "medium": 3, "high": 4}
    return order.get(sev, 0)


@router.post("/dashboard/upload")
async def upload_logs(request: Request, file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")

    # -------------------------------------------------
    # AUTO-DETECT LOG TYPE (Linux vs Windows)
    # -------------------------------------------------
    content_stripped = content.lstrip()

    content_stripped = content.lstrip()

    # CloudTrail (JSON with Records)
    if content_stripped.startswith("{") and '"Records"' in content_stripped:
        parser = CloudTrailParser()
        logs = parser.parse_from_string_json(content)

    # Windows (JSONL, one JSON per line)
    elif content_stripped.startswith("{"):
        parser = WindowsEventParser()
        logs = parser.parse_from_string(content)

    # Linux auth.log
    else:
        parser = LinuxAuthParser()
        logs = parser.parse_from_string(content)


    # -------------------------------------------------
    # Analyze + MITRE mapping
    # -------------------------------------------------
    analyzer = AIAnalyzer()
    findings = analyzer.analyze(logs)

    mapper = MitreMapper()
    mapped = [mapper.map_to_mitre(f) for f in findings]

    # -------------------------------------------------
    # KPI calculations
    # -------------------------------------------------
    severity_count = Counter()
    for f in mapped:
        severity_count[f.get("severity", "unknown")] += 1

    total_alerts = len(mapped)
    unique_ips = len({f.get("ip") for f in mapped if f.get("ip") and f.get("ip") != "unknown"})
    unique_users = len({f.get("user") for f in mapped if f.get("user") and f.get("user") != "unknown"})

    mitre_count = Counter()
    for f in mapped:
        mitre_count[f.get("mitre_id", "T0000")] += 1

    # -------------------------------------------------
    # Top IP table
    # -------------------------------------------------
    ip_stats = defaultdict(lambda: {
        "ip": None,
        "count": 0,
        "top_category": None,
        "max_severity": "info"
    })

    ip_category_counter = defaultdict(Counter)

    for f in mapped:
        ip = f.get("ip")
        if not ip or ip == "unknown":
            continue

        ip_stats[ip]["ip"] = ip
        ip_stats[ip]["count"] += 1

        cat = f.get("category", "Unknown")
        ip_category_counter[ip][cat] += 1

        sev = f.get("severity", "info")
        if _severity_rank(sev) > _severity_rank(ip_stats[ip]["max_severity"]):
            ip_stats[ip]["max_severity"] = sev

    for ip, c in ip_category_counter.items():
        ip_stats[ip]["top_category"] = c.most_common(1)[0][0]

    top_ips = sorted(
        ip_stats.values(),
        key=lambda x: (x["count"], _severity_rank(x["max_severity"])),
        reverse=True
    )[:10]

    # -------------------------------------------------
    # Time-series graph (Linux + Windows safe)
    # -------------------------------------------------
    time_buckets = Counter()

    for f in mapped:
        ts = f.get("log", {}).get("timestamp") or f.get("timestamp")
        if not ts:
            continue

        try:
            # Linux: "Jan 10 07:32:14"
            dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        except ValueError:
            try:
                # Windows ISO: "2024-01-10T08:15:01Z"
                dt = datetime.fromisoformat(ts.replace("Z", ""))
            except Exception:
                continue

        bucket = dt.strftime("%Y-%m-%d %H:00")
        time_buckets[bucket] += 1

    time_labels = sorted(time_buckets.keys())
    time_values = [time_buckets[k] for k in time_labels]

    # -------------------------------------------------
    # Sort attack list by time
    # -------------------------------------------------
    def _sort_dt(f):
        ts = f.get("log", {}).get("timestamp") or ""
        try:
            return datetime.strptime(ts, "%b %d %H:%M:%S")
        except ValueError:
            try:
                return datetime.fromisoformat(ts.replace("Z", ""))
            except Exception:
                return datetime(1900, 1, 1)

    attack_rows = sorted(mapped, key=_sort_dt)

    # -------------------------------------------------
    # Render dashboard
    # -------------------------------------------------
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "results": attack_rows,

            # KPIs
            "kpi_total": total_alerts,
            "kpi_unique_ips": unique_ips,
            "kpi_unique_users": unique_users,
            "kpi_high": severity_count.get("high", 0),
            "kpi_medium": severity_count.get("medium", 0),
            "kpi_low": severity_count.get("low", 0),
            "kpi_info": severity_count.get("info", 0),

            # Charts
            "severity_labels": list(severity_count.keys()),
            "severity_values": list(severity_count.values()),
            "mitre_labels": list(mitre_count.keys()),
            "mitre_values": list(mitre_count.values()),
            "time_labels": time_labels,
            "time_values": time_values,

            # Tables
            "top_ips": top_ips,
        }
    )
