import json
from typing import Dict, List
from dotenv import load_dotenv
import yaml
from openai import OpenAI
import os

load_dotenv()


# -------------------------------------------------
# Configuration Loader
# -------------------------------------------------
def load_config(path: str = "config.yaml") -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# -------------------------------------------------
# LLM Recommender (Advisory Only)
# -------------------------------------------------
class LLMRecommender:
    """
    LLM-based advisory engine.
    IMPORTANT:
    - Does NOT perform detection
    - Does NOT assign severity
    - Does NOT map MITRE
    - ONLY provides mitigation and prevention guidance
    """

    SYSTEM_PROMPT = """
You are a senior SOC security advisor.

Rules:
- You DO NOT perform threat detection.
- You DO NOT change severity or MITRE mapping.
- You ONLY provide mitigation and prevention advice.
- Be concise, actionable, and realistic.
- Respond ONLY with valid JSON.
"""

    USER_PROMPT_TEMPLATE = """
Given the following security incident summary, provide mitigation guidance.

Return JSON in EXACTLY this format:

{{
  "risk_summary": "",
  "immediate_actions": [],
  "preventive_controls": [],
  "priority": ""
}}

Incident summary:
{incident_summary}
"""


    def __init__(self):
        self.config = load_config()
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    # -------------------------------------------------
    # Public API
    # -------------------------------------------------
    def generate_recommendations(self, incident_summary: Dict) -> Dict:
        prompt = self.USER_PROMPT_TEMPLATE.format(
            incident_summary=json.dumps(incident_summary, indent=2)
        )

        try:
            response = self.client.chat.completions.create(
                model=self.config["openai_model"],
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )

            text = response.choices[0].message.content

            return self._safe_json_parse(text)

        except Exception as e:
            return self._fallback_response(str(e))


    # -------------------------------------------------
    # Helpers
    # -------------------------------------------------
    def _safe_json_parse(self, text: str) -> Dict:
        """
        Parse strict JSON from model output.
        Strips Markdown fences if present.
        """

        text = text.strip()

        if text.startswith("```"):
            text = text.replace("```json", "").replace("```", "").strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return self._fallback_response("Invalid JSON from model")

    def _fallback_response(self, reason: str) -> Dict:
        """
        Safe fallback if the LLM fails.
        """

        return {
            "risk_summary": "Unable to generate AI recommendations.",
            "immediate_actions": [
                "Review affected accounts and source IPs",
                "Apply temporary access restrictions",
                "Manually assess recent activity"
            ],
            "preventive_controls": [
                "Enable multi-factor authentication",
                "Harden privileged account access",
                "Improve monitoring and alerting"
            ],
            "priority": "unknown"
        }


# -------------------------------------------------
# Optional: Incident Summary Builder
# -------------------------------------------------
def build_incident_summary(findings: List[Dict]) -> Dict:
    """
    Converts analyzer output into a compact summary for LLM input.
    This SHOULD be called AFTER AIAnalyzer + MitreMapper.
    """

    categories = set()
    mitre_ids = set()
    users = set()
    ips = set()
    severities = []

    for f in findings:
        categories.add(f.get("category", "Unknown"))
        mitre_ids.add(f.get("mitre_id", "T0000"))
        if f.get("user"):
            users.add(f["user"])
        if f.get("ip"):
            ips.add(f["ip"])
        severities.append(f.get("severity", "info"))

    severity_rank = {"info": 1, "low": 2, "medium": 3, "high": 4}
    max_severity = max(severities, key=lambda s: severity_rank.get(s, 0))

    return {
        "max_severity": max_severity,
        "categories": sorted(categories),
        "mitre_techniques": sorted(mitre_ids),
        "affected_users": sorted(users),
        "affected_ips": sorted(ips),
        "event_count": len(findings)
    }
