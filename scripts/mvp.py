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

    print("[START] Überprüfe alle Manifeste im Verzeichnis...")

    for filepath in yaml_files:
        with open(filepath, 'r') as f:
            original_manifest = f.read()

        original_image, deployment_name = extract_image_and_name(original_manifest)
        if not original_image:
            continue
            
        print(f"\n[DISCOVERY] Prüfe Deployment '{deployment_name}' ({os.path.basename(filepath)}) mit Image '{original_image}'...")
        
        finding = scan_image(original_image)
        if not finding or finding.get("severity") not in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]:
            print(f"[SKIP] Keine relevanten Schwachstellen gefunden.")
            continue

        print(f"[DISCOVERY] Schwachstelle gefunden: {finding.get('severity', 'UNKNOWN')}")

        trivy_fixed = finding.get("fixed_version") or finding.get("FixedVersion")
        fixed_version = None
        base_image_name = original_image.split(":")[0]

        if trivy_fixed and image_exists_in_registry(f"{base_image_name}:{trivy_fixed}"):
            fixed_version = trivy_fixed
        
        if not fixed_version and original_image in DEMO_FALLBACK_MAP:
            fixed_version = DEMO_FALLBACK_MAP[original_image]
            
        if not fixed_version:
            print(f"[ÜBERSPRINGE] Keine sichere Version für {original_image} gefunden.")
            continue

        print(f"[AGENT] Generiere gepatchtes Manifest für {deployment_name}...")
        
        # Original-Manifest als drittes Argument übergeben
        agent_result = generate_manifest(finding, fixed_version, original_manifest)
        
        with open(filepath, "w") as f:
            f.write(agent_result['manifest'])
            
        updates_made.append(filepath)
        print(f"[SAVED] {os.path.basename(filepath)} aktualisiert.")

    if not updates_made:
        print("\n[FERTIG] Keine Updates notwendig. Beende.")
        sys.exit(0)

    print("\n[GIT] Erstelle gebündelten Pull Request...")
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
        
        print("[DONE] Pull Request erstellt!")
    except subprocess.CalledProcessError as e:
        print(f"[FEHLER] Git-Operation fehlgeschlagen: {e}")

if __name__ == "__main__":
    main()