import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "scripts"))

from src.integrations.github_pr import create_remediation_pr

REPO_NAME = "js030/vuln-remediation-platform" 
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