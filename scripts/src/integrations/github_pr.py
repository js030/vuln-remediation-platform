import os
from github import Github
from datetime import datetime

def create_pull_request(repo_name: str, file_path: str, content: str, title: str, branch_prefix: str = "remediation") -> str:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN Umgebungsvariable ist nicht gesetzt.")

    g = Github(token)
    repo = g.get_repo(repo_name)
    
    base_branch = repo.default_branch
    base_ref = repo.get_git_ref(f"heads/{base_branch}")
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_branch = f"{branch_prefix}/{timestamp}"
    repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_ref.object.sha)
    
    commit_message = f"Security: Automatisierte Behebung für {title}"
    
    try:
        contents = repo.get_contents(file_path, ref=base_branch)
        repo.update_file(contents.path, commit_message, content, contents.sha, branch=new_branch)
    except Exception:
        repo.create_file(file_path, commit_message, content, branch=new_branch)
        
    pr_title = f"Automatisierte Vulnerability Remediation: {title}"
    pr_body = "Dieser PR enthält ein durch die KI generiertes Manifest zur Behebung einer Schwachstelle.\n\nBitte vor dem Merge manuell prüfen."
    pr = repo.create_pull(title=pr_title, body=pr_body, head=new_branch, base=base_branch)
    
    return pr.html_url
