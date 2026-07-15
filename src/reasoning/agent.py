import re
import yaml
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatOllama(model="llama3.2", temperature=0)

manifest_prompt = PromptTemplate(
    input_variables=["issue_id", "issue_type", "severity", "image_name", "target_version", "issue_title"],
    template="""You are a Kubernetes remediation assistant.

Base your fixes on this standard Deployment structure:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: base-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: base-app
  template:
    metadata:
      labels:
        app: base-app
    spec:
      containers:
      - name: base-app
        image: {image_name}

Now fix this issue:
- ID: {issue_id}
- Type: {issue_type} (cve or misconfig)
- Severity: {severity}
- Title: {issue_title}

STRICT RULES:
1. If type is 'cve', update the image version EXACTLY to: {target_version}.
2. If type is 'misconfig', modify the YAML structure (e.g., add securityContext) to address the title.
3. Output ONLY valid YAML, nothing else. No explanations, no markdown code fences, no comments.
"""
)

chain = manifest_prompt | llm | StrOutputParser()

def calculate_target_version(current_version: str, fixed_version: str) -> str:
    if fixed_version:
        return fixed_version
    try:
        parts = current_version.split('.')
        if len(parts) >= 2 and parts[1].isdigit():
            return f"{parts[0]}.{int(parts[1]) + 1}.0"
    except Exception:
        pass
    return "latest"

def generate_manifest(finding: dict) -> dict:
    current_version = finding["affected_asset"].split(":")[-1] if ":" in finding["affected_asset"] else "unknown"
    fixed_version = finding.get("fixed_version")
    
    target_version = calculate_target_version(current_version, fixed_version) if finding["type"] == "cve" else current_version

    result_yaml = chain.invoke({
        "issue_id": finding["id"],
        "issue_type": finding["type"],
        "severity": finding["severity"],
        "image_name": finding["affected_asset"],
        "target_version": target_version,
        "issue_title": finding["title"]
    })

    is_valid_yaml = False
    try:
        yaml.safe_load(result_yaml)
        is_valid_yaml = True
    except yaml.YAMLError:
        pass

    version_updated = False
    matches_fixed_version = False
    
    if finding["type"] == "cve":
        match = re.search(r'image:\s*\S+:([a-zA-Z0-9\.\-]+)', result_yaml)
        if match:
            new_version = match.group(1)
            if new_version == target_version:
                version_updated = True
            if fixed_version and new_version == fixed_version:
                matches_fixed_version = True
    else:
        version_updated = True
        matches_fixed_version = True

    return {
        "manifest": result_yaml,
        "is_valid_yaml": is_valid_yaml,
        "version_updated": version_updated,
        "matches_fixed_version": matches_fixed_version
    }