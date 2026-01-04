# 🛡️ AI-Powered Cloud Threat Log Analyzer

**Rule-Based Detection with MITRE ATT&CK Mapping and LLM-Driven Security Recommendations**

---

## 📌 Overview

The **AI-Powered Cloud Threat Log Analyzer** is a security analytics platform designed to **detect, analyze, and contextualize cyber threats** across **Linux**, **Windows**, and **AWS CloudTrail** logs.

The system combines:

* **Deterministic, rule-based detection** (SOC-style)
* **MITRE ATT&CK technique mapping**
* **Aggregated incident analysis**
* **LLM-powered mitigation and prevention recommendations**
* **Interactive FastAPI dashboard**
* **Fully containerized Docker deployment**

The project is intentionally designed to reflect **real-world SOC and SIEM architectures**, where **AI assists analysts** without replacing deterministic detection logic.

---

## 🎯 Key Objectives

* Detect suspicious activity across heterogeneous log sources
* Maintain explainable and auditable detection logic
* Map alerts to the MITRE ATT&CK framework
* Aggregate events into meaningful incidents
* Use LLMs **only** for post-detection security recommendations
* Provide a clear, analyst-friendly dashboard
* Support containerized, reproducible deployment

---

## 🧠 System Architecture

```
Log Source
  ├── Linux auth.log
  ├── Windows Security Events (JSONL)
  └── AWS CloudTrail (JSON)

        ↓

Log Parsers
  ├── LinuxAuthParser
  ├── WindowsEventParser
  └── CloudTrailParser

        ↓

Rule-Based AIAnalyzer
  ├── Brute Force
  ├── Suspicious Login
  ├── Privilege Escalation
  ├── Process Creation
  ├── Persistence
  └── Credential Access

        ↓

MITRE ATT&CK Mapper
        ↓

Event Aggregation
        ↓

LLM Advisory Layer (Optional, Fail-Safe)
        ↓

FastAPI Dashboard & Reports
```

---

## 🔍 Detection Coverage

### Linux

* SSH brute-force attempts
* Successful logins from new IPs
* Public key authentication
* `sudo` privilege escalation
* Cron persistence
* Sensitive file access (`/etc/shadow`)

### Windows

* Failed logins (Event ID 4625)
* Successful logins (4624)
* Privileged logons (4672)
* Suspicious process creation (4688)
* PowerShell and temporary payload execution

### AWS CloudTrail

* Unauthorized API calls
* Failed console logins
* IAM policy modifications
* Reconnaissance API calls (`List`, `Describe`, `Get`)

---

## 🧭 MITRE ATT&CK Integration

Each detection is mapped to a relevant MITRE ATT&CK technique, for example:

| Category                        | MITRE Technique |
| ------------------------------- | --------------- |
| Brute Force                     | T1110           |
| Valid Accounts                  | T1078           |
| Privilege Escalation            | T1068           |
| Command & Scripting Interpreter | T1059           |
| IAM Misuse                      | T1484           |

This allows analysts to understand **attack intent and progression**, not just raw alerts.

---

## 🤖 LLM-Powered Security Recommendations

The system integrates an **LLM advisory layer** that:

* **Does NOT perform detection**
* **Does NOT change severity**
* **Does NOT override MITRE mapping**
* **ONLY provides mitigation and prevention guidance**

### Example Output

```
Risk Summary:
Credential brute-force followed by successful authentication
and high-risk process execution.

Immediate Actions:
• Reset affected credentials
• Block source IP addresses
• Review privileged group memberships

Preventive Controls:
• Enforce MFA for administrative users
• Harden PowerShell execution policies
• Enable account lockout thresholds

Priority: HIGH
```

If the LLM is unavailable or misconfigured, the system **gracefully falls back** to predefined security guidance.

---

## 📊 Dashboard Features

* KPI cards (alerts, severity levels, unique IPs/users)
* Severity distribution charts
* MITRE technique frequency charts
* Time-series alert visualization
* Top attacking IPs table
* Detailed incident table
* AI-generated security recommendations panel

---

## 🧪 Testing

The project includes unit tests for:

* Log parsers
* Detection logic
* MITRE mapping
* Incident aggregation
* LLM fallback behavior

Tests are designed to run **without requiring API access**, supporting CI/CD pipelines.

---

## 🐳 Dockerized Deployment

### Build the Image

```bash
docker build --no-cache -t cyber-analyzer .
```

### Run the Container

```bash
docker run -d \
  -p 80:80 \
  --name cyber_analyzer \
  --env-file .env \
  cyber-analyzer
```

### Access the Dashboard

```
http://localhost/dashboard
```

---

## ⚙️ Configuration

### `.env`

```env
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
```

### `config.yaml`

```yaml
openai_model: gpt-4o-mini
```

---

## 🛡️ Design Philosophy

This project intentionally follows **SOC best practices**:

* Detection is deterministic and explainable
* AI augments analysts, it does not replace them
* Fail-safe behavior is mandatory
* Configuration and secrets are externalized
* Docker ensures reproducibility

---

## 🚀 Future Enhancements

* Multi-tenant log ingestion
* Role-based dashboard access
* Exportable incident reports (PDF/JSON)
* MITRE-specific recommendation prompts
* LLM cost and rate-limit controls
* SIEM / SOAR integration

---

## 📚 Technologies Used

* **Python 3.11**
* **FastAPI**
* **Docker**
* **MITRE ATT&CK**
* **OpenAI API**
* **Chart.js**
* **YAML / JSON**
* **pytest**

---

## 👤 Author

**[Your Name]**
MSc Cybersecurity / Data & Security Analytics
This project was developed as a **portfolio-grade security analytics system**, demonstrating applied SOC design, cloud security monitoring, and responsible AI integration.

---

## 📄 License

This project is released for **educational and portfolio purposes**.
You are free to study, fork, and adapt the code with attribution.

* Tailor this README for **MSc submission**
* Shorten it for **recruiters**
* Add **architecture diagrams**
* Add **badges and CI status**

Just tell me.
