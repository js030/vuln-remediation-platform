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

    finding_type = None
    finding = None

    if misconfigurations:
        finding = misconfigurations[0]
        finding_type = "misconfig"
    elif vulnerabilities:
        finding = vulnerabilities[0]
        finding_type = "cve"
    else:
        raise RuntimeError("No vulnerabilities or misconfigurations found.")

    if finding_type == "misconfig":
        return {
            "id": finding.get("ID"),
            "type": "misconfig",
            "severity": finding.get("Severity", "UNKNOWN"),
            "title": finding.get("Title", finding.get("ID")),
            "affected_asset": image_name,
            "fixed_version": None,
            "raw_source": finding
        }
    
    return {
        "id": finding.get("VulnerabilityID"),
        "type": "cve",
        "severity": finding.get("Severity", "UNKNOWN"),
        "title": finding.get("Title", finding.get("VulnerabilityID")),
        "affected_asset": image_name,
        "fixed_version": finding.get("FixedVersion"),
        "raw_source": finding
    }