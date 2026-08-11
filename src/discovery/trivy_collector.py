import json
import subprocess


def normalize_vulnerability(vulnerability: dict, target: str) -> dict:
    """Convert one Trivy vulnerability finding into a normalized structure."""
    return {
        "id": vulnerability.get("VulnerabilityID"),
        "package": vulnerability.get("PkgName"),
        "installed_version": vulnerability.get("InstalledVersion"),
        "fixed_version": vulnerability.get("FixedVersion"),
        "severity": vulnerability.get("Severity", "UNKNOWN").upper(),
        "title": vulnerability.get("Title"),
        "description": vulnerability.get("Description"),
        "primary_url": vulnerability.get("PrimaryURL"),
        "target": target,
    }


def scan_image(image_ref: str) -> list[dict]:
    """
    Scan one container image with Trivy.

    Returns every vulnerability finding found by Trivy, rather than only
    returning the first CVE.
    """
    command = [
        "trivy",
        "image",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        "vuln",
        image_ref,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "Trivy was not found. Ensure that Trivy is installed and in PATH."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Trivy scan timed out for image: {image_ref}"
        ) from error

    if result.returncode != 0:
        raise RuntimeError(
            f"Trivy scan failed for {image_ref}: {result.stderr.strip()}"
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Trivy returned invalid JSON for {image_ref}: {error}"
        ) from error

    findings = []

    for result_item in report.get("Results", []) or []:
        target = result_item.get("Target", "unknown")

        for vulnerability in result_item.get("Vulnerabilities", []) or []:
            finding = normalize_vulnerability(
                vulnerability=vulnerability,
                target=target,
            )

            if finding["id"]:
                findings.append(finding)

    return findings
