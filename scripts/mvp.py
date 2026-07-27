import sys
import os
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

def image_exists_in_registry(image_ref):
    try:
        result = subprocess.run(
            ["docker", "manifest", "inspect", image_ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("[WARNING] Docker CLI not found. Skipping validation.")
        return False

def main():
    original_image = "nginx:1.14.0"
    base_image_name = original_image.split(":")[0]
    
    finding = scan_image(original_image)
    
    fixed_version = finding.get("fixed_version") or finding.get("FixedVersion")
    if not fixed_version:
        print("[ABORT] No FixedVersion found in the Trivy scan.")
        sys.exit(1)

    print(f"[DISCOVERY] {finding.get('title', 'Vulnerability')} ({finding.get('severity', 'UNKNOWN')})")
    print(f"[DISCOVERY] Secure target version identified: {fixed_version}")

    print("[AGENT] Generating corrected manifest via LangChain...")
    
    manifest_yaml = generate_manifest(finding, fixed_version)

    print("[OUTPUT]")
    print(manifest_yaml['manifest'])

    target_file = "manifests/base/01-base.yaml"
    os.makedirs(os.path.dirname(target_file), exist_ok=True)
    with open(target_file, "w") as f:
        f.write(manifest_yaml['manifest'])

    print(f"[SAVED] {target_file}")
    
    target_image_ref = f"{base_image_name}:{fixed_version}"
    print(f"[VALIDATION] Verifying physical existence of the image: {target_image_ref}...")
    
    if not image_exists_in_registry(target_image_ref):
        print(f"[ERROR] The image {target_image_ref} does not exist. Aborting commit.")
        sys.exit(1)
        
    print("[VALIDATION] Image successfully verified.")
    
    print("[GIT] Creating Pull Request...")
    branch_name = "remediation/nginx-update"
    
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
            "--body", "Automated vulnerability remediation by AI Agent.", 
            "--base", "main"
        ], check=True)
        
        print("[DONE] Pull Request created. Please check GitHub.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git/GH CLI operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()