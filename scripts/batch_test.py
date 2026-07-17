import csv
import time
from datetime import datetime
from src.discovery.trivy_collector import scan_image_all_findings
from src.reasoning.agent import generate_manifest

TEST_IMAGES = [
    "nginx:1.14.0",
    "nginx:1.15.0",
    "nginx:1.16.0",
    "httpd:2.4.54",
    "redis:5.0.0",
    "python:3.6.0",
]

REPEATS_PER_FINDING = 3
MAX_CVES_PER_IMAGE = 5

LOG_FILE = "logs/batch_evaluation_log.csv"

def run_batch_test():
    rows = []

    for image in TEST_IMAGES:
        print(f"\n=== Scanning {image} ===")
        try:
            findings = scan_image_all_findings(image, max_findings=MAX_CVES_PER_IMAGE, min_severity="HIGH")
        except Exception as e:
            print(f"[ERROR] Discovery failed for {image}: {e}")
            rows.append({
                "timestamp": datetime.now().isoformat(),
                "image": image, "cve_id": "", "severity": "",
                "run_number": "", "yaml_valid": False,
                "version_updated": False, "matches_fixed_version": False,
                "latency_seconds": "", "error": str(e)
            })
            continue

        for finding in findings:
            for run in range(1, REPEATS_PER_FINDING + 1):
                print(f"  -> {finding['id']} (run {run}/{REPEATS_PER_FINDING})")
                start = time.time()
                row = {
                    "timestamp": datetime.now().isoformat(),
                    "image": image,
                    "cve_id": finding["id"],
                    "severity": finding["severity"],
                    "run_number": run,
                    "error": ""
                }
                try:
                    agent_result = generate_manifest(finding)
                    row["latency_seconds"] = round(time.time() - start, 2)
                    row["yaml_valid"] = agent_result["is_valid_yaml"]
                    row["version_updated"] = agent_result["version_updated"]
                    row["matches_fixed_version"] = agent_result["matches_fixed_version"]
                except Exception as e:
                    row["yaml_valid"] = False
                    row["version_updated"] = False
                    row["matches_fixed_version"] = False
                    row["error"] = str(e)
                    row["latency_seconds"] = ""

                rows.append(row)

    with open(LOG_FILE, "w", newline="") as f:
        fieldnames = ["timestamp", "image", "cve_id", "severity",
                      "run_number", "yaml_valid", "version_updated", 
                      "matches_fixed_version", "latency_seconds", "error"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nBatch test complete. Results saved to {LOG_FILE}")
    print(f"Total test runs: {len(rows)}")

if __name__ == "__main__":
    run_batch_test()