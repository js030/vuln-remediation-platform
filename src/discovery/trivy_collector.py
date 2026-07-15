import subprocess
import json

def scan_image(image_name: str) -> dict:
    result = subprocess.run(
        ["trivy", "image", "--format", "json", "--scanners", "vuln,misconfig", image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        raise RuntimeError(f"Trivy returned empty output for '{image_name}'. Stderr: {result.stderr.strip()}")

    raw_data = json.loads(result.stdout)
    results = raw_data.get("Results", [])

    vulnerabilities = []
    misconfigurations = []
    
    for res in results:
        vulnerabilities.extend(res.get("Vulnerabilities", []))
        misconfigurations.extend(res.get("Misconfigurations", []))

    if misconfigurations:
        finding = misconfigurations[0]
        return {
            "id": finding.get("ID"),
            "type": "misconfig",
            "severity": finding.get("Severity", "UNKNOWN"),
            "title": finding.get("Title", finding.get("ID")),
            "affected_asset": image_name,
            "fixed_version": None,
            "raw_source": finding
        }
    elif vulnerabilities:
        finding = vulnerabilities[0]
        return {
            "id": finding.get("VulnerabilityID"),
            "type": "cve",
            "severity": finding.get("Severity", "UNKNOWN"),
            "title": finding.get("Title", finding.get("VulnerabilityID")),
            "affected_asset": image_name,
            "fixed_version": finding.get("FixedVersion"),
            "raw_source": finding
        }
    else:
        raise RuntimeError("No vulnerabilities or misconfigurations found.")

def scan_image_all_findings(image_name: str, max_findings: int = 3, min_severity: str = "HIGH") -> list:
    result = subprocess.run(
        ["trivy", "image", "--format", "json", "--scanners", "vuln,misconfig", image_name],
        capture_output=True, text=True
    )

    if not result.stdout.strip():
        return []

    raw_data = json.loads(result.stdout)
    results = raw_data.get("Results", [])

    all_findings = []
    for res in results:
     
        for vuln in res.get("Vulnerabilities", []):
            all_findings.append({
                "id": vuln.get("VulnerabilityID"),
                "type": "cve",
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title", vuln.get("VulnerabilityID")),
                "affected_asset": image_name,
                "fixed_version": vuln.get("FixedVersion"),
                "raw_source": vuln
            })

        for misconfig in res.get("Misconfigurations", []):
            all_findings.append({
                "id": misconfig.get("ID"),
                "type": "misconfig",
                "severity": misconfig.get("Severity", "UNKNOWN"),
                "title": misconfig.get("Title", misconfig.get("ID")),
                "affected_asset": image_name,
                "fixed_version": None,
                "raw_source": misconfig
            })


    severity_weights = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_sev_weight = severity_weights.get(min_severity, 0)
    
    filtered_findings = [
        f for f in all_findings 
        if severity_weights.get(f.get("severity", "UNKNOWN"), 0) >= min_sev_weight
    ]
    
   
    filtered_findings.sort(key=lambda x: severity_weights.get(x.get("severity", "UNKNOWN"), 0), reverse=True)
    
    return filtered_findings[:max_findings]