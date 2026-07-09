import subprocess
import json

def scan_image(image_name:str) -> dict:
      result = subprocess.run(
            ["trivy", "image", "--format", "json", image_name],
            capture_output=True, text=True
      )
      try:
            raw_data = json.loads(result.stdout)
            vuln = raw_data.get("Results", [])
            if not vuln or not vuln[0].get("Vulnerabilities"):
                  return {}
            vuln = vuln[0]["Vulnerabilities"][0]
      except Exception:
            return {}
      return {
            "id": vuln["VulnerabilityID"],
            "type": "cve",
            "severity": vuln.get("Severity", "UNKNOWN"),
            "title": vuln.get("Title", vuln["VulnerabilityID"]),
            "affected_asset": image_name,
            "raw_source": vuln,
      }