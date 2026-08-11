import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest


SUPPORTED_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
SUPPORTED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


APPROVED_IMAGE_REMEDIATION_MAP = {
  
    "nginx:1.14.0": "nginx:1.24.0",
    "redis:5.0.9": "redis:7.0.14",
    "httpd:2.4.49": "httpd:2.4.58",
    "mongo:3.6.0": "mongo:4.4.29",
    "prom/node-exporter:v1.0.1": "prom/node-exporter:v1.8.2",
}

MAX_RETRIES = 2

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "pipeline_metrics.jsonl")


def split_yaml_documents(content: str) -> list[str]:
    """Split a multi-document YAML file into individual YAML documents."""
    return re.split(r"(?m)^---\s*$", content)


def image_exists_in_registry(image_ref: str) -> bool:
    """Check whether a target image exists in the container registry."""
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def select_target_image(original_image: str) -> tuple[str | None, str]:
    """
    Select an approved replacement image.

    The target is determined by an approved image policy, not directly from
    Trivy FixedVersion, because a Trivy fixed version often refers to an
    operating-system package version inside an image.
    """
    target_image = APPROVED_IMAGE_REMEDIATION_MAP.get(original_image)

    if target_image:
        return target_image, "approved_image_policy"

    return None, "no_approved_image_target"


def get_workload_containers(document: dict) -> list[dict]:
    """
    Return all regular containers and init containers in a supported workload.
    """
    if not document or document.get("kind") not in SUPPORTED_WORKLOAD_KINDS:
        return []

    pod_spec = (
        document.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )

    targets = []

    for container_type, container_key in (
        ("containers", "containers"),
        ("initContainers", "initContainers"),
    ):
        for index, container in enumerate(pod_spec.get(container_key, []) or []):
            image = container.get("image")
            name = container.get("name")

            if image and name:
                targets.append(
                    {
                        "container_type": container_type,
                        "container_key": container_key,
                        "container_index": index,
                        "container_name": name,
                        "image": image,
                    }
                )

    return targets


def get_container_image(
    document: dict,
    container_key: str,
    container_name: str,
) -> str | None:
    """Return the image of one exact container identified by name."""
    pod_spec = (
        document.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )

    for container in pod_spec.get(container_key, []) or []:
        if container.get("name") == container_name:
            return container.get("image")

    return None


def validate_manifest(
    manifest_text: str,
    workload_kind: str,
    workload_name: str,
    container_key: str,
    container_name: str,
    expected_image: str,
) -> tuple[bool, str | None, float]:
    """
    Validate generated YAML and verify the exact target container image.
    """
    validation_started = time.perf_counter()

    try:
        parsed = yaml.safe_load(manifest_text)
    except yaml.YAMLError as error:
        return (
            False,
            f"yaml_syntax_error: {error}",
            time.perf_counter() - validation_started,
        )

    if not parsed:
        return (
            False,
            "empty_yaml_document",
            time.perf_counter() - validation_started,
        )

    if parsed.get("kind") != workload_kind:
        return (
            False,
            f"unexpected_workload_kind: expected={workload_kind}, "
            f"actual={parsed.get('kind')}",
            time.perf_counter() - validation_started,
        )

    actual_workload_name = parsed.get("metadata", {}).get("name")

    if actual_workload_name != workload_name:
        return (
            False,
            f"unexpected_workload_name: expected={workload_name}, "
            f"actual={actual_workload_name}",
            time.perf_counter() - validation_started,
        )

    actual_image = get_container_image(
        parsed,
        container_key,
        container_name,
    )

    if actual_image is None:
        return (
            False,
            f"target_container_not_found: {container_key}/{container_name}",
            time.perf_counter() - validation_started,
        )

    if actual_image != expected_image:
        return (
            False,
            f"target_image_mismatch: expected={expected_image}, "
            f"actual={actual_image}",
            time.perf_counter() - validation_started,
        )

    return True, None, time.perf_counter() - validation_started


def generate_manifest_with_retry(
    finding: dict,
    current_manifest: str,
    workload_kind: str,
    workload_name: str,
    container_type: str,
    container_name: str,
    original_image: str,
    target_image: str,
) -> tuple[dict, int, float]:
    """Generate a manifest proposal with limited retry handling."""
    last_result = None
    total_llm_latency = 0.0

    for attempt in range(1, MAX_RETRIES + 2):
        generation_started = time.perf_counter()

        result = generate_manifest(
            finding=finding,
            original_manifest=current_manifest,
            workload_kind=workload_kind,
            workload_name=workload_name,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
        )

        total_llm_latency += time.perf_counter() - generation_started
        last_result = result

        if result.get("manifest") and result.get("is_valid_yaml"):
            return result, attempt, total_llm_latency

    return last_result or {}, MAX_RETRIES + 1, total_llm_latency


def log_run(
    *,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    container_type: str,
    container_name: str,
    original_image: str,
    target_image: str | None,
    finding: dict | None,
    trivy_latency_seconds: float,
    llm_latency_seconds: float,
    validation_latency_seconds: float,
    end_to_end_latency_seconds: float,
    attempts: int,
    accepted: bool,
    outcome: str,
    rejection_reason: str | None = None,
) -> None:
    """Write structured performance and remediation metrics in English."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "workload_kind": workload_kind,
        "workload_name": workload_name,
        "namespace": namespace,
        "container_type": container_type,
        "container_name": container_name,
        "original_image": original_image,
        "target_image": target_image,
        "finding_id": finding.get("id") if finding else None,
        "severity": finding.get("severity") if finding else None,
        "trivy_scan_latency_seconds": round(trivy_latency_seconds, 3),
        "llm_generation_latency_seconds": round(llm_latency_seconds, 3),
        "validation_latency_seconds": round(validation_latency_seconds, 3),
        "end_to_end_latency_seconds": round(end_to_end_latency_seconds, 3),
        "attempts": attempts,
        "accepted": accepted,
        "outcome": outcome,
        "rejection_reason": rejection_reason,
    }

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry) + "\n")


def process_container(
    current_manifest: str,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    target: dict,
) -> tuple[str, bool]:
    """Scan and remediate one exact container inside a workload."""
    original_image = target["image"]
    container_name = target["container_name"]
    container_type = target["container_type"]
    container_key = target["container_key"]

    run_started = time.perf_counter()

    print(
        f"\n[DISCOVERY] {workload_kind}/{workload_name} | "
        f"{container_type}/{container_name} | image={original_image}"
    )

    trivy_started = time.perf_counter()

    try:
        finding = scan_image(original_image)
    except Exception as error:
        trivy_latency = time.perf_counter() - trivy_started
        total_latency = time.perf_counter() - run_started

        print(f"[ERROR] Trivy scan failed for {original_image}: {error}")

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            finding=None,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=0.0,
            validation_latency_seconds=0.0,
            end_to_end_latency_seconds=total_latency,
            attempts=0,
            accepted=False,
            outcome="scanner_failed",
            rejection_reason=str(error),
        )

        return current_manifest, False

    trivy_latency = time.perf_counter() - trivy_started

    if not finding:
        total_latency = time.perf_counter() - run_started

        print(f"[SKIP] No vulnerabilities found for {original_image}.")

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            finding=None,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=0.0,
            validation_latency_seconds=0.0,
            end_to_end_latency_seconds=total_latency,
            attempts=0,
            accepted=False,
            outcome="no_vulnerability",
        )

        return current_manifest, False

    if finding.get("severity") not in SUPPORTED_SEVERITIES:
        return current_manifest, False

    print(
        f"[DISCOVERY] Finding={finding.get('id')} "
        f"severity={finding.get('severity')}"
    )

    target_image, target_source = select_target_image(original_image)

    if not target_image:
        total_latency = time.perf_counter() - run_started

        print(
            f"[SKIP] No approved container-image remediation target "
            f"for {original_image}."
        )

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            finding=finding,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=0.0,
            validation_latency_seconds=0.0,
            end_to_end_latency_seconds=total_latency,
            attempts=0,
            accepted=False,
            outcome="no_approved_target",
            rejection_reason=(
                "no_approved_container_image_target; "
                "trivy_fixed_version_not_used_as_image_tag"
            ),
        )

        return current_manifest, False

    if not image_exists_in_registry(target_image):
        total_latency = time.perf_counter() - run_started

        print(f"[SKIP] Approved target image is unavailable: {target_image}")

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            finding=finding,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=0.0,
            validation_latency_seconds=0.0,
            end_to_end_latency_seconds=total_latency,
            attempts=0,
            accepted=False,
            outcome="target_image_unavailable",
            rejection_reason=f"approved_target_not_available: {target_source}",
        )

        return current_manifest, False

    print(
        f"[AGENT] Generating remediation for {container_type}/{container_name}: "
        f"{original_image} -> {target_image}"
    )

    agent_result, attempts, llm_latency = generate_manifest_with_retry(
        finding=finding,
        current_manifest=current_manifest,
        workload_kind=workload_kind,
        workload_name=workload_name,
        container_type=container_type,
        container_name=container_name,
        original_image=original_image,
        target_image=target_image,
    )

    manifest_text = agent_result.get("manifest")

    if not manifest_text:
        total_latency = time.perf_counter() - run_started

        print(f"[REJECTED] No usable LLM output for {container_name}.")

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            finding=finding,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=llm_latency,
            validation_latency_seconds=0.0,
            end_to_end_latency_seconds=total_latency,
            attempts=attempts,
            accepted=False,
            outcome="rejected",
            rejection_reason="no_manifest_returned",
        )

        return current_manifest, False

    valid, rejection_reason, validation_latency = validate_manifest(
        manifest_text=manifest_text,
        workload_kind=workload_kind,
        workload_name=workload_name,
        container_key=container_key,
        container_name=container_name,
        expected_image=target_image,
    )

    total_latency = time.perf_counter() - run_started

    if not valid:
        print(f"[REJECTED] {container_name}: {rejection_reason}")

        log_run(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_type=container_type,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            finding=finding,
            trivy_latency_seconds=trivy_latency,
            llm_latency_seconds=llm_latency,
            validation_latency_seconds=validation_latency,
            end_to_end_latency_seconds=total_latency,
            attempts=attempts,
            accepted=False,
            outcome="rejected",
            rejection_reason=rejection_reason,
        )

        return current_manifest, False

    print(
        f"[SAVED] {workload_kind}/{workload_name} | "
        f"{container_type}/{container_name} | "
        f"attempts={attempts} | "
        f"end_to_end_latency={total_latency:.2f}s"
    )

    log_run(
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_type=container_type,
        container_name=container_name,
        original_image=original_image,
        target_image=target_image,
        finding=finding,
        trivy_latency_seconds=trivy_latency,
        llm_latency_seconds=llm_latency,
        validation_latency_seconds=validation_latency,
        end_to_end_latency_seconds=total_latency,
        attempts=attempts,
        accepted=True,
        outcome="remediated",
    )

    return manifest_text, True


def process_document(chunk: str, filepath: str) -> tuple[str, bool]:
    """Process all supported containers in one YAML workload document."""
    try:
        document = yaml.safe_load(chunk)
    except yaml.YAMLError as error:
        print(f"[SKIP] Invalid YAML in {os.path.basename(filepath)}: {error}")
        return chunk, False

    if not document or document.get("kind") not in SUPPORTED_WORKLOAD_KINDS:
        return chunk, False

    workload_kind = document.get("kind")
    workload_name = document.get("metadata", {}).get("name", "unknown")
    namespace = document.get("metadata", {}).get("namespace", "default")

    initial_targets = get_workload_containers(document)

    if not initial_targets:
        return chunk, False

    current_manifest = chunk
    document_changed = False

    # Re-parse after each accepted remediation because the manifest may have
    # changed during the previous container remediation.
    for initial_target in initial_targets:
        try:
            current_document = yaml.safe_load(current_manifest)
        except yaml.YAMLError:
            break

        current_image = get_container_image(
            current_document,
            initial_target["container_key"],
            initial_target["container_name"],
        )

        if not current_image:
            continue

        target = dict(initial_target)
        target["image"] = current_image

        current_manifest, container_changed = process_container(
            current_manifest=current_manifest,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            target=target,
        )

        document_changed = document_changed or container_changed

    return current_manifest, document_changed


def create_or_update_pull_request(updates_made: list[str]) -> None:
    """Push a remediation branch and create or update one open PR."""
    branch_name = "remediation/bulk-update"

    print("\n[GIT] Creating or updating remediation Pull Request...")

    try:
        subprocess.run(["git", "checkout", "main"], check=True)

        subprocess.run(
            ["git", "branch", "-D", branch_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        subprocess.run(["git", "checkout", "-b", branch_name], check=True)

        for filepath in updates_made:
            subprocess.run(["git", "add", filepath], check=True)

        subprocess.run(
            [
                "git",
                "commit",
                "-m",
                "security: automated remediation of vulnerable container images",
            ],
            check=True,
        )

        subprocess.run(
            ["git", "push", "origin", branch_name, "--force"],
            check=True,
        )

        existing_pr = subprocess.run(
            [
                "gh",
                "pr",
                "list",
                "--head",
                branch_name,
                "--base",
                "main",
                "--state",
                "open",
                "--json",
                "url",
                "--jq",
                ".[0].url // empty",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        existing_url = existing_pr.stdout.strip()

        if existing_url:
            print(f"[DONE] Existing remediation PR updated: {existing_url}")
            return

        created_pr = subprocess.run(
            [
                "gh",
                "pr",
                "create",
                "--title",
                "Security Patch: Container Image Remediation",
                "--body",
                (
                    "Automated remediation proposal generated by the "
                    "vulnerability remediation agent.\n\n"
                    "Please review all image-version updates before merging."
                ),
                "--base",
                "main",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        print(f"[DONE] Pull Request created: {created_pr.stdout.strip()}")

    except subprocess.CalledProcessError as error:
        print(f"[ERROR] Git or Pull Request operation failed: {error}")


def main() -> None:
    manifest_dir = os.path.join(PROJECT_ROOT, "manifests", "base")
    yaml_files = sorted(glob.glob(os.path.join(manifest_dir, "*.yaml")))

    updates_made = []

    print("[START] Scanning Kubernetes workload manifests...")
    print(
        "[INFO] Supported workload kinds: "
        + ", ".join(sorted(SUPPORTED_WORKLOAD_KINDS))
    )

    for filepath in yaml_files:
        with open(filepath, "r", encoding="utf-8") as manifest_file:
            full_content = manifest_file.read()

        chunks = split_yaml_documents(full_content)
        updated_chunks = []
        file_changed = False

        for chunk in chunks:
            if not chunk.strip():
                updated_chunks.append(chunk)
                continue

            updated_chunk, changed = process_document(chunk, filepath)
            updated_chunks.append(updated_chunk)
            file_changed = file_changed or changed

        if file_changed:
            with open(filepath, "w", encoding="utf-8") as manifest_file:
                manifest_file.write(
                    "\n---\n".join(item.strip("\n") for item in updated_chunks)
                )
                manifest_file.write("\n")

            updates_made.append(filepath)

    if not updates_made:
        print("\n[DONE] No patchable findings found. No Pull Request created.")
        return

    create_or_update_pull_request(updates_made)


if __name__ == "__main__":
    main()
