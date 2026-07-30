import sys
import os
import subprocess
import glob
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

DEMO_FALLBACK_MAP = {
    "nginx:1.14.0": "1.24.0",
    "redis:5.0.9": "7.0.14",
    "httpd:2.4.49": "2.4.58"
}

def image_exists_in_registry(image_ref):
    try:
        result = subprocess.run(["docker", "manifest", "inspect", image_ref], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except FileNotFoundError:
        return False

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

def main():
    manifest_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'manifests', 'base'))
    yaml_files = glob.glob(os.path.join(manifest_dir, "*.yaml"))
    
    updates_made = []

    print("[START] Checking all manifests in directory...")

    for filepath in yaml_files:
        with open(filepath, 'r') as f:
            original_manifest = f.read()

        original_image, deployment_name = extract_image_and_name(original_manifest)
        if not original_image:
            continue
            
        print(f"\n[DISCOVERY] Checking deployment '{deployment_name}' ({os.path.basename(filepath)}) with image '{original_image}'...")
        
        finding = scan_image(original_image)
        if not finding or finding.get("severity") not in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]:
            print(f"[SKIP] No relevant vulnerabilities found.")
            continue

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
            continue

        print(f"[AGENT] Generating patched manifest for {deployment_name}...")
        
        # Pass original manifest as third argument
        agent_result = generate_manifest(finding, fixed_version, original_manifest)
        
        with open(filepath, "w") as f:
            f.write(agent_result['manifest'])
            
        updates_made.append(filepath)
        print(f"[SAVED] {os.path.basename(filepath)} updated.")

    if not updates_made:
        print("\n[DONE] No updates necessary. Exiting.")
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