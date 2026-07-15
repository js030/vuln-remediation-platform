import subprocess
import json
import re

def scan_image(image_name: str) -> dict:
    result = subprocess.run(
        ["trivy", "image", "--format", "json", image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        raise RuntimeError(
            f"Trivy returned empty output for '{image_name}'. "
            f"Stderr: {result.stderr.strip()}"
        )

    raw_data = json.loads(result.stdout)
    vulnerabilities = raw_data["Results"][0]["Vulnerabilities"]

    base_package = image_name.split(":")[0]
    vuln = next(
        (v for v in vulnerabilities if v["PkgName"].lower() == base_package.lower()),
        vulnerabilities[0]
    )

    return {
        "id": vuln["VulnerabilityID"],
        "type": "cve",
        "severity": vuln.get("Severity", "UNKNOWN"),
        "title": vuln.get("Title", vuln["VulnerabilityID"]),
        "affected_asset": image_name,
        "fixed_version": vuln.get("FixedVersion", None),
        "raw_source": vuln
    }
def scan_image_all_findings(image_name: str) -> list[dict]:
    result = subprocess.run(
        ["trivy", "image", "--format", "json", image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        raise RuntimeError(
            f"Trivy returned empty output for '{image_name}'. "
            f"Stderr: {result.stderr.strip()}"
        )

    raw_data = json.loads(result.stdout)
    vulnerabilities = raw_data["Results"][0]["Vulnerabilities"]

    findings = []
    for vuln in vulnerabilities[:5]:
        findings.append({
            "id": vuln["VulnerabilityID"],
            "type": "cve",
            "severity": vuln.get("Severity", "UNKNOWN"),
            "title": vuln.get("Title", vuln["VulnerabilityID"]),
            "affected_asset": image_name,
            "fixed_version": vuln.get("FixedVersion", None),
            "raw_source": vuln
        })
    
    return findings

import re

def scan_image_all_findings(image_name: str, max_findings: int = 5, min_severity: str = None, official_cve_only: bool = False) -> list[dict]:
    result = subprocess.run(
        ["trivy", "image", "--format", "json", image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        raise RuntimeError(
            f"Trivy returned empty output for '{image_name}'. "
            f"Stderr: {result.stderr.strip()}"
        )

    raw_data = json.loads(result.stdout)
    vulnerabilities = raw_data["Results"][0]["Vulnerabilities"]

    if official_cve_only:
        vulnerabilities = [
            v for v in vulnerabilities
            if re.match(r"^CVE-\d{4}-\d+$", v["VulnerabilityID"])
        ]

    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if min_severity:
        min_level = severity_order.get(min_severity.upper(), 0)
        vulnerabilities = [
            v for v in vulnerabilities
            if severity_order.get(v.get("Severity", "LOW").upper(), 0) >= min_level
        ]
    base_package = image_name.split(":")[0]
    package_matches = [v for v in vulnerabilities if v["PkgName"].lower() == base_package.lower()]
    vulnerabilities = package_matches if package_matches else vulnerabilities

    findings = []
    for vuln in vulnerabilities[:max_findings]:
        findings.append({
            "id": vuln["VulnerabilityID"],
            "type": "cve",
            "severity": vuln.get("Severity", "UNKNOWN"),
            "title": vuln.get("Title", vuln["VulnerabilityID"]),
            "affected_asset": image_name,
            "fixed_version": vuln.get("FixedVersion", None),
            "raw_source": vuln
        })
    return findings