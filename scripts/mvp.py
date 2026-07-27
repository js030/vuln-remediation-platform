import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

def main():
    finding = scan_image("nginx:1.14.0")
    print(f"[DISCOVERY] {finding['title']} ({finding['severity']})")

    print("[AGENT] Generating corrected manifest via LangChain...")
    manifest_yaml = generate_manifest(finding)

    print("[OUTPUT]")
    print(manifest_yaml['manifest'])

    target_file = "manifests/base/01-base.yaml"
    with open(target_file, "w") as f:
        f.write(manifest_yaml['manifest'])

    print(f"[SAVED] {target_file}")
    
    print("[GIT] Creating Pull Request...")
    branch_name = "remediation/nginx-update"
    
    os.system("git checkout main")
    os.system(f"git branch -D {branch_name} 2>/dev/null") 
    os.system(f"git checkout -b {branch_name}")
    
  
    os.system(f"git add {target_file}")
    os.system('git commit -m "security: update nginx image to remediate vulnerabilities"')
    os.system(f"git push origin {branch_name} --force")

    os.system('gh pr create --title "Security Patch: Update Nginx to secure version" --body "Automated vulnerability remediation by AI Agent." --base main')
    
    print("[DONE] Pull Request created. Please check GitHub.")

if __name__ == "__main__":
    main()