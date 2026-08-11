import copy
import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

import yaml

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    ),
)

from src.discovery.trivy_collector import scan_image
from src.policy.image_policy import (
    load_image_policy,
    select_approved_target,
)
from src.reasoning.agent import generate_pr_description


SUPPORTED_WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
}

RELEVANT_SEVERITIES = {
    "HIGH",
    "CRITICAL",
}

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

MANIFEST_DIRECTORY = os.path.join(
    PROJECT_ROOT,
    "manifests",
    "base",
)

POLICY_FILE = os.path.join(
    PROJECT_ROOT,
    "policies",
    "approved-images.yaml",
)

LOG_FILE = os.path.join(
    PROJECT_ROOT,
    "logs",
    "pipeline_metrics.jsonl",
)

BRANCH_NAME = "remediation/team-approved-image-baselines"


def split_yaml_documents(content: str) -> list[str]:
    """Split a multi-document YAML file into individual YAML documents."""
    return re.split(r"(?m)^---\s*$", content)


def image_exists_in_registry(image_ref: str) -> bool:
    """Check whether a target image exists in its registry."""
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_pod_spec(document: dict) -> dict:
    """Return the pod specification of a Kubernetes workload."""
    return (
        document.get("spec", {})
        .get("template", {})
        .get("spec", {})
    )


def get_workload_containers(document: dict) -> list[dict]:
    """Return regular containers and init containers of supported workloads."""
    if not document:
        return []

    if document.get("kind") not in SUPPORTED_WORKLOAD_KINDS:
        return []

    pod_spec = get_pod_spec(document)
    targets = []

    for container_key in ("containers", "initContainers"):
        for index, container in enumerate(
            pod_spec.get(container_key, []) or []
        ):
            name = container.get("name")
            image = container.get("image")

            if name and image:
                targets.append(
                    {
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
    """Return the image field of one exact named container."""
    pod_spec = get_pod_spec(document)

    for container in pod_spec.get(container_key, []) or []:
        if container.get("name") == container_name:
            return container.get("image")

    return None


def update_container_image(
    document: dict,
    container_key: str,
    container_name: str,
    target_image: str,
) -> bool:
    """
    Deterministically update exactly one image field.

    No LLM is used for this operation, so the YAML update is predictable.
    """
    pod_spec = get_pod_spec(document)

    for container in pod_spec.get(container_key, []) or []:
        if container.get("name") == container_name:
            container["image"] = target_image
            return True

    return False


def finding_ids(findings: list[dict]) -> set[str]:
    """Return all CVE IDs from a Trivy finding list."""
    return {
        finding["id"]
        for finding in findings
        if finding.get("id")
    }


def filter_findings_by_severity(
    findings: list[dict],
    severities: set[str],
) -> list[dict]:
    """Return findings matching one of the requested severities."""
    return [
        finding
        for finding in findings
        if finding.get("severity") in severities
    ]


def high_critical_cve_ids(findings: list[dict]) -> set[str]:
    """Return HIGH and CRITICAL CVE IDs."""
    return finding_ids(
        filter_findings_by_severity(
            findings=findings,
            severities=RELEVANT_SEVERITIES,
        )
    )


def critical_cve_ids(findings: list[dict]) -> set[str]:
    """Return CRITICAL CVE IDs."""
    return finding_ids(
        filter_findings_by_severity(
            findings=findings,
            severities={"CRITICAL"},
        )
    )


def verify_target_image(
    original_findings: list[dict],
    target_findings: list[dict],
    image_policy: dict,
) -> tuple[bool, dict]:
    """
    Compare Trivy results of original and approved target images.

    The update is rejected if:
    - no relevant HIGH/CRITICAL CVE is resolved;
    - the policy requires all original relevant CVEs to disappear but some remain;
    - new CRITICAL CVEs appear in the target image.
    """
    original_relevant = high_critical_cve_ids(original_findings)
    target_relevant = high_critical_cve_ids(target_findings)

    original_critical = critical_cve_ids(original_findings)
    target_critical = critical_cve_ids(target_findings)

    resolved_cves = sorted(original_relevant - target_relevant)
    remaining_cves = sorted(original_relevant & target_relevant)
    new_critical_cves = sorted(target_critical - original_critical)

    require_all_resolved = image_policy.get(
        "require_all_high_critical_resolved",
        False,
    )

    require_no_new_critical = image_policy.get(
        "require_no_new_critical_cves",
        True,
    )

    evidence = {
        "resolved_cves": resolved_cves,
        "remaining_cves": remaining_cves,
        "new_critical_cves": new_critical_cves,
    }

    if not resolved_cves:
        evidence["reason"] = (
            "approved_target_does_not_improve_relevant_cves"
        )
        return False, evidence

    if require_all_resolved and remaining_cves:
        evidence["reason"] = "relevant_cves_remain_in_target_image"
        return False, evidence

    if require_no_new_critical and new_critical_cves:
        evidence["reason"] = "new_critical_cves_in_target_image"
        return False, evidence

    evidence["reason"] = None
    return True, evidence


def validate_only_target_image_changed(
    original_document: dict,
    updated_document: dict,
    container_key: str,
    container_name: str,
    target_image: str,
) -> tuple[bool, str | None]:
    """
    Validate that no field besides the target container image changed.
    """
    expected_document = copy.deepcopy(original_document)

    changed = update_container_image(
        document=expected_document,
        container_key=container_key,
        container_name=container_name,
        target_image=target_image,
    )

    if not changed:
        return False, "target_container_not_found_in_original_document"

    if expected_document != updated_document:
        return False, "unexpected_manifest_change_detected"

    return True, None


def log_run(**entry: object) -> None:
    """Write structured pipeline metrics to JSONL."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    entry["timestamp_utc"] = datetime.now(
        timezone.utc
    ).isoformat()

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(
            json.dumps(entry, ensure_ascii=False) + "\n"
        )


def process_container(
    document: dict,
    workload_kind: str,
    workload_name: str,
    namespace: str,
    target: dict,
    policy: dict,
) -> tuple[dict, bool, str | None]:
    """Scan, validate and remediate exactly one container."""
    original_image = target["image"]
    container_key = target["container_key"]
    container_name = target["container_name"]

    started = time.perf_counter()

    print(
        f"\n[DISCOVERY] {workload_kind}/{workload_name} | "
        f"{container_key}/{container_name} | "
        f"image={original_image}"
    )

    try:
        original_findings = scan_image(original_image)
    except Exception as error:
        print(f"[ERROR] Original image scan failed: {error}")

        log_run(
            outcome="original_scanner_failed",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            rejection_reason=str(error),
        )

        return document, False, None

    relevant_original_findings = filter_findings_by_severity(
        original_findings,
        RELEVANT_SEVERITIES,
    )

    if not relevant_original_findings:
        print("[SKIP] No HIGH or CRITICAL vulnerabilities found.")

        log_run(
            outcome="no_relevant_vulnerability",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            original_finding_count=len(original_findings),
            rejection_reason=None,
        )

        return document, False, None

    target_image, selection_reason, image_policy = select_approved_target(
        original_image=original_image,
        policy=policy,
    )

    if not target_image:
        print(
            f"[SKIP] No approved target image: {selection_reason}"
        )

        log_run(
            outcome="no_approved_target",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=None,
            rejection_reason=selection_reason,
        )

        return document, False, None

    if not image_exists_in_registry(target_image):
        print(f"[SKIP] Target image unavailable: {target_image}")

        log_run(
            outcome="target_image_unavailable",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            rejection_reason="docker_manifest_inspect_failed",
        )

        return document, False, None

    try:
        target_findings = scan_image(target_image)
    except Exception as error:
        print(f"[ERROR] Target image scan failed: {error}")

        log_run(
            outcome="target_scanner_failed",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            rejection_reason=str(error),
        )

        return document, False, None

    accepted, evidence = verify_target_image(
        original_findings=original_findings,
        target_findings=target_findings,
        image_policy=image_policy,
    )

    if not accepted:
        print(
            "[SKIP] Approved target rejected by Trivy validation: "
            f"{evidence['reason']}"
        )

        log_run(
            outcome="target_rejected_by_security_validation",
            accepted=False,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            resolved_cves=evidence["resolved_cves"],
            remaining_cves=evidence["remaining_cves"],
            new_critical_cves=evidence["new_critical_cves"],
            rejection_reason=evidence["reason"],
        )

        return document, False, None

    original_document = copy.deepcopy(document)

    changed = update_container_image(
        document=document,
        container_key=container_key,
        container_name=container_name,
        target_image=target_image,
    )

    if not changed:
        print("[REJECTED] Target container not found.")
        return original_document, False, None

    valid, rejection_reason = validate_only_target_image_changed(
        original_document=original_document,
        updated_document=document,
        container_key=container_key,
        container_name=container_name,
        target_image=target_image,
    )

    if not valid:
        print(f"[REJECTED] Invalid manifest change: {rejection_reason}")
        return original_document, False, None

    policy_owner = image_policy.get("owner", "unknown-team")

    pr_description = generate_pr_description(
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        original_image=original_image,
        target_image=target_image,
        policy_owner=policy_owner,
        resolved_cves=evidence["resolved_cves"],
        remaining_cves=evidence["remaining_cves"],
        new_critical_cves=evidence["new_critical_cves"],
    )

    elapsed = time.perf_counter() - started

    print(
        f"[SAVED] {original_image} -> {target_image} | "
        f"resolved={len(evidence['resolved_cves'])} | "
        f"duration={elapsed:.2f}s"
    )

    log_run(
        outcome="remediated",
        accepted=True,
        workload_kind=workload_kind,
        workload_name=workload_name,
        namespace=namespace,
        container_name=container_name,
        original_image=original_image,
        target_image=target_image,
        resolved_cves=evidence["resolved_cves"],
        remaining_cves=evidence["remaining_cves"],
        new_critical_cves=evidence["new_critical_cves"],
        duration_seconds=round(elapsed, 3),
        rejection_reason=None,
    )

    return document, True, pr_description


def process_document(
    document: dict,
    policy: dict,
) -> tuple[dict, bool, list[str]]:
    """Process every regular and init container in one workload."""
    if not document:
        return document, False, []

    workload_kind = document.get("kind")

    if workload_kind not in SUPPORTED_WORKLOAD_KINDS:
        return document, False, []

    metadata = document.get("metadata", {})
    workload_name = metadata.get("name", "unknown")
    namespace = metadata.get("namespace", "default")

    targets = get_workload_containers(document)

    if not targets:
        return document, False, []

    document_changed = False
    pr_descriptions = []

    for initial_target in targets:
        current_image = get_container_image(
            document=document,
            container_key=initial_target["container_key"],
            container_name=initial_target["container_name"],
        )

        if not current_image:
            continue

        target = dict(initial_target)
        target["image"] = current_image

        document, changed, pr_description = process_container(
            document=document,
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            target=target,
            policy=policy,
        )

        document_changed = document_changed or changed

        if pr_description:
            pr_descriptions.append(pr_description)

    return document, document_changed, pr_descriptions


def create_or_update_pull_request(
    updated_files: list[str],
    pr_descriptions: list[str],
) -> None:
    """Push the remediation branch and create or update one PR."""
    if not updated_files:
        return

    pr_body = "\n\n---\n\n".join(pr_descriptions)

    if not pr_body:
        pr_body = (
            "Automated container image remediation proposal.\n\n"
            "Human review is required before merge."
        )

    try:
        subprocess.run(["git", "checkout", "main"], check=True)
        subprocess.run(["git", "pull", "origin", "main"], check=True)

        subprocess.run(
            ["git", "checkout", "-B", BRANCH_NAME],
            check=True,
        )

        subprocess.run(
            ["git", "add", *updated_files],
            check=True,
        )

        staged_changes = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            check=False,
        )

        if staged_changes.returncode == 0:
            print("[GIT] No staged changes. No Pull Request created.")
            return

        subprocess.run(
            [
                "git",
                "commit",
                "-m",
                "security: update images to approved baselines",
            ],
            check=True,
        )

        subprocess.run(
            [
                "git",
                "push",
                "--set-upstream",
                "origin",
                BRANCH_NAME,
                "--force",
            ],
            check=True,
        )

        existing_pr = subprocess.run(
            [
                "gh",
                "pr",
                "list",
                "--head",
                BRANCH_NAME,
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
            subprocess.run(
                [
                    "gh",
                    "pr",
                    "edit",
                    existing_url,
                    "--body",
                    pr_body,
                ],
                check=True,
            )
            print(f"[DONE] Existing Pull Request updated: {existing_url}")
            return

        created_pr = subprocess.run(
            [
                "gh",
                "pr",
                "create",
                "--title",
                "security: remediation via approved image baselines",
                "--body",
                pr_body,
                "--base",
                "main",
                "--head",
                BRANCH_NAME,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        print(f"[DONE] Pull Request created: {created_pr.stdout.strip()}")

    except subprocess.CalledProcessError as error:
        print(f"[ERROR] Git or GitHub operation failed: {error}")


def main() -> None:
    """Run the complete remediation pipeline."""
    policy = load_image_policy(POLICY_FILE)

    yaml_files = sorted(
        glob.glob(
            os.path.join(MANIFEST_DIRECTORY, "*.yaml")
        )
    )

    if not yaml_files:
        print(f"[DONE] No YAML files found in: {MANIFEST_DIRECTORY}")
        return

    updated_files = []
    all_pr_descriptions = []

    print("[START] Team-approved image remediation pipeline")
    print(
        "[INFO] Supported workload kinds: "
        + ", ".join(sorted(SUPPORTED_WORKLOAD_KINDS))
    )

    for filepath in yaml_files:
        with open(filepath, "r", encoding="utf-8") as file:
            full_content = file.read()

        chunks = split_yaml_documents(full_content)
        updated_chunks = []
        file_changed = False

        for chunk in chunks:
            if not chunk.strip():
                updated_chunks.append(chunk)
                continue

            try:
                document = yaml.safe_load(chunk)
            except yaml.YAMLError as error:
                print(
                    f"[SKIP] Invalid YAML in "
                    f"{os.path.basename(filepath)}: {error}"
                )
                updated_chunks.append(chunk)
                continue

            updated_document, changed, pr_descriptions = process_document(
                document=document,
                policy=policy,
            )

            if changed:
                updated_chunks.append(
                    yaml.safe_dump(
                        updated_document,
                        sort_keys=False,
                    ).strip()
                )
            else:
                updated_chunks.append(chunk.strip())

            file_changed = file_changed or changed
            all_pr_descriptions.extend(pr_descriptions)

        if file_changed:
            with open(filepath, "w", encoding="utf-8") as file:
                file.write("\n---\n".join(updated_chunks))
                file.write("\n")

            updated_files.append(filepath)

    if not updated_files:
        print("\n[DONE] No approved and Trivy-verified remediation found.")
        return

    create_or_update_pull_request(
        updated_files=updated_files,
        pr_descriptions=all_pr_descriptions,
    )


if __name__ == "__main__":
    main()
