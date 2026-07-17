import os
import sys

# Erzwingt den absoluten Pfad zum scripts-Ordner
current_dir = os.path.dirname(os.path.abspath(__file__))
scripts_dir = os.path.join(current_dir, "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from src.integrations.github_pr import create_remediation_pr

# HIER ANPASSEN BEVOR AUSGEFUEHRT WIRD
REPO_NAME = "DEIN_GITHUB_USERNAME/DEIN_REPO_NAME" 
MANIFEST_DIR = "manifests/remediated"

try:
    print("Starting PR generation...")
    pr_url = create_remediation_pr(repo_name=REPO_NAME, manifests_dir=MANIFEST_DIR)
    
    if pr_url:
        print(f"Success! Pull Request URL: {pr_url}")
    else:
        print("No PR was created.")
except Exception as e:
    print(f"An error occurred: {e}")
