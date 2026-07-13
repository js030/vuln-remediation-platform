import subprocess
import json

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