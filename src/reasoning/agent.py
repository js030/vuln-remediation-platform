import re
import yaml
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatOllama(
    model="llama3.2",
    temperature=0
)

manifest_prompt = PromptTemplate(
    input_variables=["cve_id", "severity", "image_name", "target_version"],
    template="""You are a Kubernetes remediation assistant.

EXAMPLE:
Input: image=nginx, target_version=1.25.4
Correct output:
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.25.4

Now fix this vulnerability:
- CVE: {cve_id}
- Severity: {severity}
- Affected image: {image_name}

STRICT RULES:
1. Update the image version EXACTLY to: {target_version}.
2. Do NOT change replicas, ports, labels, or any other field.
3. Follow the EXACT same structure as the example.
4. Output ONLY valid YAML, nothing else. No explanations, no markdown code fences, no comments.
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
    
    target_version = calculate_target_version(current_version, fixed_version)

    result_yaml = chain.invoke({
        "cve_id": finding["id"],
        "severity": finding["severity"],
        "image_name": finding["affected_asset"],
        "target_version": target_version
    })

    is_valid_yaml = False
    try:
        yaml.safe_load(result_yaml)
        is_valid_yaml = True
    except yaml.YAMLError:
        pass

    version_updated = False
    matches_fixed_version = False
    
    match = re.search(r'image:\s*\S+:([a-zA-Z0-9\.\-]+)', result_yaml)
    if match:
        new_version = match.group(1)
        if new_version == target_version:
            version_updated = True
        if fixed_version and new_version == fixed_version:
            matches_fixed_version = True

    return {
        "manifest": result_yaml,
        "is_valid_yaml": is_valid_yaml,
        "version_updated": version_updated,
        "matches_fixed_version": matches_fixed_version
    }