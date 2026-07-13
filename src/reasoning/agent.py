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
    input_variables=["cve_id", "severity", "image_name", "current_version", "fixed_version"],
    template="""You are a Kubernetes remediation assistant.

EXAMPLE:
Input: image=nginx, current_version=1.14.0
Correct output (only image tag changed, everything else identical to original):
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
- Current version: {current_version}
- Known fixed version (if available): {fixed_version}

STRICT RULES:
1. If a known fixed version is provided above (not "not specified"), use that exact version.
2. Otherwise, choose a realistic, higher stable version. Do NOT reuse {current_version}.
3. Do NOT change replicas, ports, labels, or any other field unless explicitly required for the fix.
4. Follow the EXACT same structure as the example.
5. Output ONLY valid YAML, nothing else. No explanations, no markdown code fences, no comments.
"""
)

chain = manifest_prompt | llm | StrOutputParser()


def generate_manifest(finding: dict) -> str:
    current_version = finding["affected_asset"].split(":")[-1] if ":" in finding["affected_asset"] else "unknown"

    result = chain.invoke({
        "cve_id": finding["id"],
        "severity": finding["severity"],
        "image_name": finding["affected_asset"],
        "current_version": current_version,
        "fixed_version": finding.get("fixed_version") or "not specified"
    })

    try:
        yaml.safe_load(result)
        print("[VALIDATION] YAML is syntactically valid.")
    except yaml.YAMLError as e:
        print(f"[VALIDATION] WARNING: Invalid YAML generated: {e}")

    match = re.search(r'image:\s*\S+:(\d+\.\d+\.\d+)', result)
    if match:
        new_version = match.group(1)
        print(f"[VALIDATION] Extracted new version: {new_version} (original: {current_version})")
        if new_version <= current_version:
            print("[VALIDATION] WARNING: New version is not higher than original — possible hallucination.")
    else:
        print("[VALIDATION] WARNING: Could not extract version number for comparison.")

    return result