#!/usr/bin/env python3
"""
LLM Security Lab - Final consolidated report generator.
Loads Garak, PyRIT, and Augustus JSON outputs; normalizes to a common schema;
maps to OWASP LLM Top 10; assigns severity; writes final_security_report.json.
Production-grade: logging, error handling, works if one or more tool outputs are missing.
"""
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
LAB_ROOT = SCRIPT_DIR.parent
REPORTS_DIR = LAB_ROOT / "reports"
FINAL_DIR = REPORTS_DIR / "final"
GARAK_PATH = REPORTS_DIR / "garak" / "garak_results.json"
PYRIT_PATH = REPORTS_DIR / "pyrit" / "pyrit_results.json"
AUGUSTUS_PATH = REPORTS_DIR / "augustus" / "augustus_results.json"
OUTPUT_PATH = FINAL_DIR / "final_security_report.json"

OWASP_LLM_TOP_10 = [
    "LLM01 - Prompt Injection",
    "LLM02 - Insecure Output Handling",
    "LLM03 - Training Data Poisoning",
    "LLM04 - Model Denial of Service",
    "LLM05 - Supply Chain Vulnerabilities",
    "LLM06 - Sensitive Information Disclosure",
    "LLM07 - Insecure Plugin Design",
    "LLM08 - Excessive Agency",
    "LLM09 - Overreliance",
    "LLM10 - Model Theft",
]

CRITICAL_CATEGORIES = {"LLM01 - Prompt Injection", "LLM06 - Sensitive Information Disclosure", "LLM08 - Excessive Agency"}

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
LOG_DATE = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt=LOG_DATE)
logger = logging.getLogger(__name__)


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Safely load JSON file. Returns None on missing file or invalid JSON."""
    if not path.exists():
        logger.warning("File not found: %s", path)
        return None
    try:
        # Windows PowerShell often writes UTF-8 with BOM; utf-8-sig safely handles both.
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.warning("Invalid JSON in %s: %s", path, e)
        return None
    except OSError as e:
        logger.warning("Could not read %s: %s", path, e)
        return None


def _normalize_garak(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract and normalize findings from Garak report structure."""
    out: List[Dict[str, Any]] = []
    raw_results = data.get("results")
    results = raw_results if isinstance(raw_results, list) else []
    if not results and isinstance(data.get("source"), str) and "none" not in data.get("source", "").lower():
        # Single .report.jsonl style: array of line objects
        if "results" in data:
            results = data["results"]
        else:
            results = [data]
    for r in results:
        if not isinstance(r, dict):
            continue
        # Garak report lines can have: probe, detector, score, hit, etc.
        success = r.get("hit") if "hit" in r else r.get("success")
        if success is None and "score" in r:
            success = float(r.get("score", 0)) > 0.5
        if success is None:
            success = False
        probe = r.get("probe") or r.get("probe_name") or "unknown"
        desc = r.get("description") or r.get("message") or str(probe)
        out.append({
            "tool": "garak",
            "vulnerability_type": _map_garak_probe_to_owasp(probe),
            "description": desc,
            "success": bool(success),
            "severity": None,  # assigned later
            "evidence": r.get("response") or r.get("output") or r.get("evidence"),
        })
    return out


def _map_garak_probe_to_owasp(probe: str) -> str:
    """Map Garak probe name/tag to OWASP LLM Top 10 category."""
    p = (probe or "").lower()
    if "prompt" in p or "injection" in p or "llm01" in p:
        return "LLM01 - Prompt Injection"
    if "output" in p or "llm02" in p:
        return "LLM02 - Insecure Output Handling"
    if "poison" in p or "llm03" in p:
        return "LLM03 - Training Data Poisoning"
    if "dos" in p or "denial" in p or "llm04" in p:
        return "LLM04 - Model Denial of Service"
    if "supply" in p or "llm05" in p:
        return "LLM05 - Supply Chain Vulnerabilities"
    if "disclos" in p or "pii" in p or "secret" in p or "llm06" in p:
        return "LLM06 - Sensitive Information Disclosure"
    if "plugin" in p or "llm07" in p:
        return "LLM07 - Insecure Plugin Design"
    if "agency" in p or "llm08" in p:
        return "LLM08 - Excessive Agency"
    if "overrelian" in p or "llm09" in p:
        return "LLM09 - Overreliance"
    if "theft" in p or "llm10" in p:
        return "LLM10 - Model Theft"
    return "LLM01 - Prompt Injection"  # default for generic probes


def _normalize_pyrit(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract and normalize findings from PyRIT output."""
    out: List[Dict[str, Any]] = []
    raw_findings = data.get("findings")
    findings = raw_findings if isinstance(raw_findings, list) else []
    for f in findings:
        if not isinstance(f, dict):
            continue
        vuln = (f.get("vulnerability_type") or "prompt_injection").lower()
        owasp = "LLM01 - Prompt Injection"
        if "information" in vuln or "disclos" in vuln:
            owasp = "LLM06 - Sensitive Information Disclosure"
        elif "jailbreak" in vuln:
            owasp = "LLM01 - Prompt Injection"
        out.append({
            "tool": "pyrit",
            "vulnerability_type": owasp,
            "description": f.get("description") or vuln,
            "success": bool(f.get("success", False)),
            "severity": None,
            "evidence": f.get("evidence"),
        })
    return out


def _normalize_augustus(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract and normalize findings from Augustus JSON output."""
    out: List[Dict[str, Any]] = []
    
    # Handle the raw unstructured JSON output produced by Augustus directly
    if isinstance(data, dict):
        if "results" in data:
            results = data["results"]
        elif "error" in data:
            return out
        else:
            # It's a single flat object, not wrapped in results
            results = [data]
    elif isinstance(data, list):
        results = data
    else:
        results = []

    for r in results:
        if not isinstance(r, dict):
            continue
        # Augustus: PROBE, DETECTOR, PASSED, SCORE, STATUS (VULN = attack succeeded)
        status = (r.get("STATUS") or r.get("status") or "").upper()
        success = status == "VULN"
        if "STATUS" not in r and "status" not in r:
            passed = r.get("passed", r.get("PASSED"))
            if passed is not None:
                success = not bool(passed)  # PASSED=false often means vulnerable
        probe = r.get("probe") or r.get("PROBE") or "unknown"
        out.append({
            "tool": "augustus",
            "vulnerability_type": _map_garak_probe_to_owasp(probe),
            "description": r.get("description") or str(probe),
            "success": bool(success),
            "severity": None,
            "evidence": r.get("response") or r.get("evidence"),
        })
    return out


def _assign_severity(f: Dict[str, Any]) -> str:
    """Assign severity: Critical (success + LLM01/06/08), High (success), Low (not success)."""
    success = f.get("success", False)
    cat = f.get("vulnerability_type") or ""
    if success and cat in CRITICAL_CATEGORIES:
        return "Critical"
    if success:
        return "High"
    return "Low"


def _build_heatmap(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Risk heatmap: by OWASP category and severity counts."""
    heat: Dict[str, Dict[str, int]] = {}
    for f in findings:
        cat = f.get("vulnerability_type") or "Unknown"
        sev = f.get("severity") or "Low"
        if cat not in heat:
            heat[cat] = {"Critical": 0, "High": 0, "Low": 0}
        heat[cat][sev] = heat[cat].get(sev, 0) + 1
    return heat


def _overall_risk(critical: int, high: int, low: int) -> str:
    """Overall risk rating from counts."""
    if critical > 0:
        return "Critical"
    if high > 0:
        return "High"
    if low > 0:
        return "Medium"
    return "Low"


def generate_final_report() -> bool:
    """Load all tool outputs, normalize, assign severity, write final report."""
    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    all_findings: List[Dict[str, Any]] = []
    model_metadata: Dict[str, Any] = {
        "endpoint": "http://localhost:11434/v1",
        "model": "llama3:1b",
        "no_openai_key": True,
    }

    # Garak
    garak_data = _load_json(GARAK_PATH)
    if garak_data is not None:
        all_findings.extend(_normalize_garak(garak_data))
        logger.info("Loaded Garak: %d findings", len(_normalize_garak(garak_data)))
    else:
        logger.info("Skipping Garak (missing or invalid file)")

    # PyRIT
    pyrit_data = _load_json(PYRIT_PATH)
    if pyrit_data is not None:
        norm = _normalize_pyrit(pyrit_data)
        all_findings.extend(norm)
        logger.info("Loaded PyRIT: %d findings", len(norm))
    else:
        logger.info("Skipping PyRIT (missing or invalid file)")

    # Augustus
    augustus_data = _load_json(AUGUSTUS_PATH)
    if augustus_data is not None:
        norm = _normalize_augustus(augustus_data)
        all_findings.extend(norm)
        logger.info("Loaded Augustus: %d findings", len(norm))
    else:
        logger.info("Skipping Augustus (missing or invalid file)")

    # Assign severity to each finding
    for f in all_findings:
        f["severity"] = _assign_severity(f)

    critical_count = sum(1 for f in all_findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in all_findings if f.get("severity") == "High")
    low_count = sum(1 for f in all_findings if f.get("severity") == "Low")

    executive_summary = {
        "total_findings": len(all_findings),
        "critical_count": critical_count,
        "high_count": high_count,
        "low_count": low_count,
        "overall_risk_rating": _overall_risk(critical_count, high_count, low_count),
    }

    risk_heatmap = _build_heatmap(all_findings)

    report = {
        "generated_at_utc": _utc_ts(),
        "executive_summary": executive_summary,
        "risk_heatmap": risk_heatmap,
        "owasp_llm_top_10_reference": OWASP_LLM_TOP_10,
        "findings": all_findings,
        "model_metadata": model_metadata,
        "sources": {
            "garak": str(GARAK_PATH),
            "pyrit": str(PYRIT_PATH),
            "augustus": str(AUGUSTUS_PATH),
        },
    }

    try:
        with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info("Final report written to %s", OUTPUT_PATH)
        
        # Also write the HTML report version
        html_out = OUTPUT_PATH.with_suffix(".html")
        _write_html_report(report, html_out)
        return True
    except OSError as e:
        logger.error("Failed to write final report: %s", e)
        return False

def _write_html_report(data: Dict[str, Any], output_path: Path):
    """Write an HTML dashboard version of the report."""
    exec_summary = data.get("executive_summary", {})
    heatmap = data.get("risk_heatmap", {})
    findings = data.get("findings", [])

    # Map risk to colors
    risk_colors = {
        "Critical": "#dc3545", # Red
        "High": "#fd7e14",     # Orange
        "Medium": "#ffc107",   # Yellow
        "Low": "#28a745"       # Green
    }
    header_color = risk_colors.get(exec_summary.get("overall_risk_rating", "Low"), "#6c757d")

    # Pre-extract data variables to keep f-string clean
    generated_at_utc = data.get("generated_at_utc", "Unknown")
    model_metadata = data.get("model_metadata", {})
    model_name = model_metadata.get("model", "Unknown")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Security Lab - Final Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #212529; }}
        .header {{ background-color: {header_color}; color: white; padding: 20px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0; color: white; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .stat-box {{ display: inline-block; width: 200px; padding: 15px; margin-right: 15px; border-radius: 8px; color: white; text-align: center; }}
        .stat-critical {{ background-color: #dc3545; }}
        .stat-high {{ background-color: #fd7e14; }}
        .stat-low {{ background-color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; border: 1px solid #dee2e6; text-align: left; }}
        th {{ background-color: #e9ecef; font-weight: bold; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
        .badge-critical {{ background-color: #dc3545; }}
        .badge-high {{ background-color: #fd7e14; }}
        .badge-low {{ background-color: #28a745; }}
        pre {{ background-color: #f1f3f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>LLM Security Final Report</h1>
        <p>Generated at: {generated_at_utc} | Model: {model_name}</p>
        <h2>Overall Risk: {exec_summary.get("overall_risk_rating", "Unknown")}</h2>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <div class="stat-box stat-critical">
            <h3>{exec_summary.get("critical_count", 0)}</h3>
            <p>Critical Findings</p>
        </div>
        <div class="stat-box stat-high">
            <h3>{exec_summary.get("high_count", 0)}</h3>
            <p>High Findings</p>
        </div>
        <div class="stat-box stat-low">
            <h3>{exec_summary.get("low_count", 0)}</h3>
            <p>Low Findings</p>
        </div>
    </div>

    <div class="card">
        <h2>Risk Heatmap by Category</h2>
        <table>
            <thead>
                <tr>
                    <th>OWASP Category</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Low</th>
                </tr>
            </thead>
            <tbody>
"""
    # Build Heatmap rows
    for cat, counts in heatmap.items():
        html += f"""
                <tr>
                    <td>{cat}</td>
                    <td>{counts.get("Critical", 0)}</td>
                    <td>{counts.get("High", 0)}</td>
                    <td>{counts.get("Low", 0)}</td>
                </tr>"""

    html += """
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Detailed Findings ({len(findings)})</h2>
"""
    # Build Detailed Findings
    for idx, f in enumerate(findings):
        sev = f.get("severity", "Low")
        sev_class = "badge-low"
        if sev == "Critical":
            sev_class = "badge-critical"
        elif sev == "High":
            sev_class = "badge-high"
            
        evidence = f.get("evidence", "No evidence provided.")
        if not evidence:
            evidence = "None"
            
        html += f"""
        <div style="border-left: 4px solid {risk_colors.get(sev, '#ccc')}; padding-left: 15px; margin-bottom: 20px;">
            <h3>#{idx + 1} - {f.get("vulnerability_type", "Unknown")} <span class="badge {sev_class}">{sev}</span></h3>
            <p><strong>Tool:</strong> {f.get("tool", "Unknown").title()} | <strong>Success:</strong> {f.get("success", False)}</p>
            <p><strong>Description/Probe:</strong> {f.get("description", "Unknown")}</p>
            <strong>Evidence:</strong>
            <pre><code>{evidence}</code></pre>
        </div>
        """

    html += """
    </div>
</body>
</html>
"""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("HTML report written to %s", output_path)
    except OSError as e:
        logger.error("Failed to write HTML report: %s", e)


if __name__ == "__main__":
    try:
        ok = generate_final_report()
        sys.exit(0 if ok else 1)
    except Exception as e:
        logger.exception("Unexpected error")
        sys.exit(1)
