import sys
import os
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

# Deterministisches Fallback-Mapping für die Demo-Umgebung
DEMO_FALLBACK_MAP = {
    "nginx:1.14.0": "1.24.0",
    "redis:5.0.9": "7.0.14",
    "httpd:2.4.49": "2.4.58"
}

def image_exists_in_registry(image_ref):
    """
    Prüft via docker manifest inspect, ob das Image in der Registry existiert.
    """
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("[WARNUNG] Docker CLI nicht gefunden. Überspringe Validierung.")
        return False

def main():
    # Für den MVP-Test hartkodiert. Du kannst dies später dynamisch machen.
    original_image = "nginx:1.14.0" 
    base_image_name = original_image.split(":")[0]
    
    print(f"[DISCOVERY] Starte Scan für {original_image}...")
    finding = scan_image(original_image)
    
    print(f"[DISCOVERY] Gefundene Schwachstelle: {finding.get('title', 'Vulnerability')} ({finding.get('severity', 'UNKNOWN')})")
    
    # 1. Versuch: Trivy FixedVersion (Oft nur ein OS-Paket, kein Image-Tag)
    trivy_fixed_version = finding.get("fixed_version") or finding.get("FixedVersion")
    fixed_version = None
    
    if trivy_fixed_version:
        target_image_ref = f"{base_image_name}:{trivy_fixed_version}"
        print(f"[VALIDATION] Prüfe Trivy-Version: {target_image_ref}...")
        if image_exists_in_registry(target_image_ref):
            fixed_version = trivy_fixed_version
            print(f"[VALIDATION] Trivy-Version {trivy_fixed_version} ist ein valides Docker-Image.")
        else:
            print(f"[VALIDATION] Trivy-Version {trivy_fixed_version} existiert nicht als Docker-Tag (vermutlich ein OS-Paket).")

    # 2. Versuch: Deterministisches Demo-Mapping
    if not fixed_version:
        print("[FALLBACK] Prüfe statisches Demo-Mapping...")
        if original_image in DEMO_FALLBACK_MAP:
            fixed_version = DEMO_FALLBACK_MAP[original_image]
            print(f"[FALLBACK] Nutze sichere Demo-Version: {fixed_version}")
        else:
            print(f"[ABBRUCH] Weder eine valide Trivy-Version noch ein Fallback für {original_image} gefunden.")
            sys.exit(1)

    print(f"[DISCOVERY] Finale Zielversion für Agenten: {fixed_version}")
    print("[AGENT] Generating corrected manifest via LangChain...")
    
    # Übergabe der gesicherten Version an den Agenten
    manifest_yaml = generate_manifest(finding, fixed_version)

    print("[OUTPUT]")
    print(manifest_yaml['manifest'])

    # Zielpfad anpassen, falls nötig
    target_file = f"manifests/base/{base_image_name}_{original_image.split(':')[1]}.yaml"
    os.makedirs(os.path.dirname(target_file), exist_ok=True)
    with open(target_file, "w") as f:
        f.write(manifest_yaml['manifest'])

    print(f"[SAVED] {target_file}")
    
    # Finaler Sanity Check vor Git
    final_image_ref = f"{base_image_name}:{fixed_version}"
    if not image_exists_in_registry(final_image_ref):
         print(f"[FEHLER] Finale Image-Version {final_image_ref} existiert nicht. Abbruch.")
         sys.exit(1)
         
    # 3. Git-Operationen
    print("[GIT] Creating Pull Request...")
    branch_name = f"remediation/{base_image_name}-update"
    
    try:
        subprocess.run(["git", "checkout", "main"], check=True)
        subprocess.run(["git", "branch", "-D", branch_name], stderr=subprocess.DEVNULL) 
        subprocess.run(["git", "checkout", "-b", branch_name], check=True)
        
        subprocess.run(["git", "add", target_file], check=True)
        commit_msg = f"security: update {base_image_name} image to {fixed_version} to remediate vulnerabilities"
        subprocess.run(["git", "commit", "-m", commit_msg], check=True)
        subprocess.run(["git", "push", "origin", branch_name, "--force"], check=True)

        pr_title = f"Security Patch: Update {base_image_name} to secure version {fixed_version}"
        subprocess.run([
            "gh", "pr", "create", 
            "--title", pr_title, 
            "--body", "Automated vulnerability remediation by AI Agent.\n\n_Note: Target version resolved via verified demo fallback mapping._", 
            "--base", "main"
        ], check=True)
        
        print("[DONE] Pull Request created. Please check GitHub.")
    except subprocess.CalledProcessError as e:
        print(f"[FEHLER] Git/GH CLI Operation fehlgeschlagen: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()