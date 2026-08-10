import sys
import os
import subprocess
import glob
import re
import time
import json
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

DEMO_FALLBACK_MAP = {
    "nginx:1.14.0": "1.24.0",
    "redis:5.0.9": "7.0.14",
    "httpd:2.4.49": "2.4.58"
}

MAX_RETRIES = 2
LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs', 'pipeline_metrics.jsonl'))


def image_exists_in_registry(image_ref):
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def split_yaml_documents(content):
    """Teilt eine Multi-Dokument-YAML-Datei anhand von '---' in einzelne
    Text-Chunks auf, ohne die Formatierung der einzelnen Dokumente zu verändern."""
    chunks = re.split(r'(?m)^---\s*$', content)
    return chunks


def extract_image_and_name(yaml_content):
    try:
        doc = yaml.safe_load(yaml_content)
        if doc and doc.get("kind") == "Deployment":
            name = doc.get("metadata", {}).get("name", "unknown")
            containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            if containers:
                return containers[0].get("image"), name
    except Exception:
        pass
    return None, None


def apply_targeted_image_fix(manifest_text, original_image, base_image_name, fixed_version):
    """Ersetzt gezielt nur die Image-Zeile des ursprünglichen Images,
    statt pauschal alle 'image:'-Vorkommen zu überschreiben."""
    escaped_original = re.escape(original_image)
    patched, count = re.subn(
        rf'image:\s*{escaped_original}\b',
        f'image: {base_image_name}:{fixed_version}',
        manifest_text,
        count=1
    )
    if count == 0:
        return manifest_text, False
    return patched, True


def validate_final_manifest(manifest_text, expected_image=None):
    """Letzte Validierungsschranke, bevor ein Manifest übernommen wird."""
    try:
        parsed = yaml.safe_load(manifest_text)
    except yaml.YAMLError as e:
        return False, f"YAML-Syntaxfehler: {e}"

    if not parsed or parsed.get("kind") != "Deployment":
        return False, "Kein valides Deployment-Objekt (kind fehlt oder falsch)"

    if expected_image:
        try:
            actual_image = parsed["spec"]["template"]["spec"]["containers"][0]["image"]
        except (KeyError, IndexError, TypeError):
            return False, "Image-Feld nicht auffindbar"

        if actual_image != expected_image:
            return False, f"Image-Feld inkorrekt: erwartet '{expected_image}', erhalten '{actual_image}'"

    return True, None


def generate_manifest_with_retry(finding, fixed_version, original_manifest, max_retries=MAX_RETRIES):
    """Ruft den Agenten auf und wiederholt bei ungültigem Output bis zu max_retries mal."""
    last_result = None
    for attempt in range(1, max_retries + 2):
        try:
            result = generate_manifest(finding, fixed_version, original_manifest)
        except Exception as e:
            result = {
                "manifest": None,
                "is_valid_yaml": False,
                "version_updated": False,
                "matches_fixed_version": False,
                "error": str(e),
            }
        last_result = result
        if result.get("is_valid_yaml") and result.get("version_updated"):
            return result, attempt
    return last_result, max_retries + 1


def log_run(deployment_name, original_image, fixed_version, finding, agent_result, latency, attempts, accepted, rejection_reason=None):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "deployment": deployment_name,
        "original_image": original_image,
        "fixed_version": fixed_version,
        "severity": finding.get("severity") if finding else None,
        "latency_seconds": round(latency, 2),
        "attempts": attempts,
        "is_valid_yaml": agent_result.get("is_valid_yaml") if agent_result else None,
        "version_updated": agent_result.get("version_updated") if agent_result else None,
        "matches_fixed_version": agent_result.get("matches_fixed_version") if agent_result else None,
        "accepted": accepted,
        "rejection_reason": rejection_reason,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def process_document(chunk, filepath):
    """Verarbeitet ein einzelnes YAML-Dokument (aus einer Multi-Dokument-Datei
    oder einer Single-Dokument-Datei) und gibt (neuer_inhalt, wurde_geaendert) zurück."""
    original_image, deployment_name = extract_image_and_name(chunk)
    if not original_image:
        return chunk, False

    print(f"\n[DISCOVERY] Checking deployment '{deployment_name}' ({os.path.basename(filepath)}) with image '{original_image}'...")

    try:
        finding = scan_image(original_image)
    except Exception as e:
        print(f"[ERROR] Trivy scan failed for {original_image}: {e}")
        log_run(deployment_name, original_image, None, {}, None, 0.0, 0, accepted=False,
                 rejection_reason=f"trivy_scan_failed: {e}")
        return chunk, False

    if not finding or finding.get("severity") not in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]:
        print(f"[SKIP] No relevant vulnerabilities found.")
        return chunk, False

    print(f"[DISCOVERY] Vulnerability found: {finding.get('severity', 'UNKNOWN')}")

    trivy_fixed = finding.get("fixed_version") or finding.get("FixedVersion")
    fixed_version = None
    base_image_name = original_image.split(":")[0]

    if trivy_fixed and image_exists_in_registry(f"{base_image_name}:{trivy_fixed}"):
        fixed_version = trivy_fixed

    if not fixed_version and original_image in DEMO_FALLBACK_MAP:
        fixed_version = DEMO_FALLBACK_MAP[original_image]

    if not fixed_version:
        print(f"[SKIP] No secure version found for {original_image}.")
        return chunk, False

    print(f"[AGENT] Generating patched manifest for {deployment_name}...")

    start = time.time()
    agent_result, attempts = generate_manifest_with_retry(finding, fixed_version, chunk)
    latency = time.time() - start

    if not agent_result or not agent_result.get("manifest"):
        print(f"[REJECTED] {deployment_name}: LLM lieferte keinen verwertbaren Output.")
        log_run(deployment_name, original_image, fixed_version, finding, agent_result or {},
                 latency, attempts, accepted=False, rejection_reason="no_manifest_returned")
        return chunk, False

    manifest_text = agent_result['manifest']

    manifest_text, replaced = apply_targeted_image_fix(
        manifest_text, original_image, base_image_name, fixed_version
    )

    expected_image = f"{base_image_name}:{fixed_version}"
    final_valid, rejection_reason = validate_final_manifest(manifest_text, expected_image=expected_image)

    if not final_valid:
        print(f"[REJECTED] {deployment_name}: wird NICHT übernommen ({rejection_reason}).")
        log_run(deployment_name, original_image, fixed_version, finding, agent_result,
                 latency, attempts, accepted=False, rejection_reason=rejection_reason)
        return chunk, False

    print(f"[SAVED] {deployment_name} in {os.path.basename(filepath)} updated. (Versuche: {attempts}, Latenz: {latency:.2f}s)")
    log_run(deployment_name, original_image, fixed_version, finding, agent_result,
             latency, attempts, accepted=True)

    return manifest_text, True


def main():
    manifest_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'manifests', 'base'))
    yaml_files = glob.glob(os.path.join(manifest_dir, "*.yaml"))

    updates_made = []

    print("[START] Checking all manifests in directory...")

    for filepath in yaml_files:
        with open(filepath, 'r') as f:
            full_content = f.read()

        doc_chunks = split_yaml_documents(full_content)
        new_chunks = []
        file_changed = False

        for chunk in doc_chunks:
            if not chunk.strip():
                new_chunks.append(chunk)
                continue

            new_content, changed = process_document(chunk, filepath)
            new_chunks.append(new_content)
            if changed:
                file_changed = True

        if file_changed:
            with open(filepath, "w") as f:
                f.write("\n---\n".join(c.strip("\n") for c in new_chunks))
            updates_made.append(filepath)

    if not updates_made:
        print("\n[DONE] No updates necessary or all candidates rejected. Exiting.")
        sys.exit(0)

    print("\n[GIT] Creating bundled Pull Request...")
    branch_name = "remediation/bulk-update"

    try:
        subprocess.run(["git", "checkout", "main"], check=True)
        subprocess.run(["git", "branch", "-D", branch_name], stderr=subprocess.DEVNULL)
        subprocess.run(["git", "checkout", "-b", branch_name], check=True)

        for file in updates_made:
            subprocess.run(["git", "add", file], check=True)

        subprocess.run(["git", "commit", "-m", "security: automated bulk remediation of vulnerable deployments"], check=True)
        subprocess.run(["git", "push", "origin", branch_name, "--force"], check=True)

        subprocess.run([
            "gh", "pr", "create",
            "--title", "Security Patch: Bulk update of vulnerable deployments",
            "--body", "Automated vulnerability remediation by AI Agent across multiple deployments.",
            "--base", "main"
        ], check=True)

        print("[DONE] Pull Request created!")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git operation failed: {e}")


if __name__ == "__main__":
    main()

# Am Anfang der Datei (nach imports):
import os
from src.discovery.live_cluster_scanner import scan_all_live_workloads, compare_git_vs_live

# In der main() Funktion (vor manifest_dir Loop):

def main():
    # ... bestehender Code ...
    
    manifest_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'manifests', 'base'))
    yaml_files = glob.glob(os.path.join(manifest_dir, "*.yaml"))
    
    # NEU: Optional Live-Cluster-Scanning
    SCAN_LIVE_CLUSTER = os.getenv("SCAN_LIVE_CLUSTER", "false").lower() == "true"
    
    if SCAN_LIVE_CLUSTER:
        print("\n[CLUSTER-MODE] Scanning live cluster workloads...")
        live_workloads = scan_all_live_workloads()
        
        # Drift-Detection
        git_images = []
        for filepath in yaml_files:
            with open(filepath, 'r') as f:
                for doc in yaml.safe_load_all(f):
                    if doc and doc.get("kind") == "Deployment":
                        containers = doc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
                        for c in containers:
                            git_images.append(c.get("image"))
        
        drift = compare_git_vs_live(git_images, live_workloads)
        if drift["only_in_live"]:
            print(f"\n[DRIFT] Images running in cluster but not in Git:")
            for img in drift["only_in_live"]:
                print(f"  - {img}")
        
        # Scan live workloads
        for workload in live_workloads:
            print(f"\n[DISCOVERY] {workload['type']}/{workload['name']} in {workload['namespace']}: {workload['image']}")
            
            try:
                finding = scan_image(workload['image'])
                if finding and finding.get("severity") in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]:
                    print(f"[DISCOVERY] Vulnerability found: {finding.get('severity')}")
                    # ... rest der Logik wie normal ...
            except Exception as e:
                print(f"[ERROR] Scan failed: {e}")
    
    else:
        # Originale Git-basierte Logik
        print("[GIT-MODE] Scanning manifests from Git...")
        # ... bestehender Code ...
