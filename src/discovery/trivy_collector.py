import json
import subprocess


SEVERITY_WEIGHTS = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def scan_image(image_name: str) -> dict | None:
    """
    Scan one container image and return the highest-severity CVE finding.

    Returns:
        dict: Highest-severity CVE finding.
        None: No vulnerabilities were found.

    Raises:
        RuntimeError: Trivy could not scan the image.
    """
    result = subprocess.run(
        [
            "trivy",
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--skip-version-check",
            image_name,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Trivy scan failed for '{image_name}': {result.stderr.strip()}"
        )

    if not result.stdout.strip():
        raise RuntimeError(f"Trivy returned empty output for '{image_name}'.")

    raw_data = json.loads(result.stdout)
    vulnerabilities = []

    for result_item in raw_data.get("Results", []):
        vulnerabilities.extend(result_item.get("Vulnerabilities", []))

    if not vulnerabilities:
        return None

    vulnerabilities.sort(
        key=lambda finding: SEVERITY_WEIGHTS.get(
            finding.get("Severity", "UNKNOWN"),
            0,
        ),
        reverse=True,
    )

    finding = vulnerabilities[0]

    return {
        "id": finding.get("VulnerabilityID"),
        "type": "cve",
        "severity": finding.get("Severity", "UNKNOWN"),
        "title": finding.get("Title", finding.get("VulnerabilityID")),
        "affected_asset": image_name,
        "fixed_version": finding.get("FixedVersion"),
        "raw_source": finding,
    }


def scan_image_all_findings(
    image_name: str,
    max_findings: int = 3,
    min_severity: str = "HIGH",
) -> list:
    """Return multiple CVE findings sorted by severity."""
    result = subprocess.run(
        [
            "trivy",
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--skip-version-check",
            image_name,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0 or not result.stdout.strip():
        return []

    raw_data = json.loads(result.stdout)
    findings = []

    for result_item in raw_data.get("Results", []):
        for vulnerability in result_item.get("Vulnerabilities", []):
            findings.append(
                {
                    "id": vulnerability.get("VulnerabilityID"),
                    "type": "cve",
                    "severity": vulnerability.get("Severity", "UNKNOWN"),
                    "title": vulnerability.get(
                        "Title",
                        vulnerability.get("VulnerabilityID"),
                    ),
                    "affected_asset": image_name,
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "raw_source": vulnerability,
                }
            )

    minimum_weight = SEVERITY_WEIGHTS.get(min_severity, 0)

    findings = [
        finding
        for finding in findings
        if SEVERITY_WEIGHTS.get(finding["severity"], 0) >= minimum_weight
    ]

    findings.sort(
        key=lambda finding: SEVERITY_WEIGHTS.get(
            finding["severity"],
            0,
        ),
        reverse=True,
    )

    return findings[:max_findings]
