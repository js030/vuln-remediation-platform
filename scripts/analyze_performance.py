import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path


LOG_FILE = Path("logs/pipeline_metrics.jsonl")


def average(values):
    return round(statistics.mean(values), 3) if values else 0.0


def percentage(part, total):
    return round((part / total * 100), 1) if total else 0.0


def main():
    if not LOG_FILE.exists():
        print("No metrics file found: logs/pipeline_metrics.jsonl")
        return

    records = []

    for line in LOG_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue

        item = json.loads(line)

        # Only evaluate the current metric schema.
        if "outcome" in item and "timestamp_utc" in item:
            records.append(item)

    if not records:
        print("No current-schema metrics records found.")
        print("Run the remediation pipeline at least once.")
        return

    remediated = [
        item for item in records
        if item.get("outcome") == "remediated"
    ]

    rejected = [
        item for item in records
        if item.get("outcome") == "rejected"
    ]

    skipped = [
        item for item in records
        if item.get("outcome") in {
            "no_vulnerability",
            "no_approved_target",
            "target_image_unavailable",
        }
    ]

    scanner_failed = [
        item for item in records
        if item.get("outcome") == "scanner_failed"
    ]

    patchable = remediated + rejected

    trivy_latencies = [
        item["trivy_scan_latency_seconds"]
        for item in records
        if isinstance(item.get("trivy_scan_latency_seconds"), (int, float))
    ]

    llm_latencies = [
        item["llm_generation_latency_seconds"]
        for item in patchable
        if isinstance(item.get("llm_generation_latency_seconds"), (int, float))
    ]

    end_to_end_latencies = [
        item["end_to_end_latency_seconds"]
        for item in records
        if isinstance(item.get("end_to_end_latency_seconds"), (int, float))
    ]

    first_attempt_successes = [
        item for item in remediated
        if item.get("attempts") == 1
    ]

    retry_count = sum(
        item.get("attempts", 0) > 1
        for item in patchable
    )

    print("=" * 70)
    print("AI-ASSISTED VULNERABILITY REMEDIATION - PERFORMANCE REPORT")
    print("=" * 70)

    print("\n1. COVERAGE")
    print(f"Total container remediation attempts: {len(records)}")
    print(f"Successful remediations: {len(remediated)}")
    print(f"Rejected LLM proposals: {len(rejected)}")
    print(f"Skipped findings: {len(skipped)}")
    print(f"Scanner failures: {len(scanner_failed)}")

    print("\n2. REMEDIATION QUALITY")
    print(
        "Remediation Success Rate (successful / patchable): "
        f"{percentage(len(remediated), len(patchable))}%"
    )
    print(
        "First-Attempt Success Rate (successful first attempt / patchable): "
        f"{percentage(len(first_attempt_successes), len(patchable))}%"
    )
    print(
        "Retry Rate (patchable findings requiring >1 attempt): "
        f"{percentage(retry_count, len(patchable))}%"
    )

    print("\n3. LATENCY INDICATORS")
    print(f"Average Trivy Scan Latency: {average(trivy_latencies)} seconds")
    print(f"Average LLM Generation Latency: {average(llm_latencies)} seconds")
    print(f"Average End-to-End Latency: {average(end_to_end_latencies)} seconds")

    print("\n4. RESULTS BY SEVERITY")
    by_severity = defaultdict(list)

    for item in records:
        by_severity[item.get("severity") or "NO_FINDING"].append(item)

    print(f"{'Severity':<14}{'Attempts':>10}{'Remediated':>14}{'Success Rate':>16}")

    for severity, items in sorted(by_severity.items()):
        successful = sum(
            item.get("outcome") == "remediated"
            for item in items
        )

        print(
            f"{severity:<14}"
            f"{len(items):>10}"
            f"{successful:>14}"
            f"{percentage(successful, len(items)):>15.1f}%"
        )

    print("\n5. OUTCOME DISTRIBUTION")
    outcomes = Counter(item.get("outcome", "unknown") for item in records)

    for outcome, count in outcomes.most_common():
        print(f"{outcome:<30}{count}")

    print("\n6. REJECTION / SKIP REASONS")
    reasons = Counter(
        item.get("rejection_reason")
        for item in records
        if item.get("rejection_reason")
    )

    if reasons:
        for reason, count in reasons.most_common():
            print(f"{count:>4}  {reason}")
    else:
        print("No rejection or skip reasons recorded.")

    print("\nKPI DEFINITIONS")
    print("- Remediation Success Rate: successful remediations / patchable findings")
    print("- First-Attempt Success Rate: successful first attempts / patchable findings")
    print("- Retry Rate: patchable findings requiring more than one LLM attempt")
    print("- End-to-End Latency: scan, LLM generation, validation and decision time")
    print("=" * 70)


if __name__ == "__main__":
    main()
