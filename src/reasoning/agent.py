import re
import yaml
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatOllama(model="llama3.2", temperature=0)

manifest_prompt = PromptTemplate(
    input_variables=["image_name", "fixed_version"],
    template="""You are a strict configuration generator with no creative freedom.
Your only task is to update the 'image' field in the provided Kubernetes manifest.

Base your fix on this standard Deployment structure:
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

STRUCTURAL REQUIREMENTS:
1. Replace the tag of the current image version exactly with: {fixed_version}
2. The resulting image field must match the format of the original image name but with the new tag.
3. Do absolutely not change any other values, keys, indentation, or formatting.
4. Do not add any explanations, markdown blocks, or comments.
5. Return exclusively the raw YAML manifest.
"""
)

chain = manifest_prompt | llm | StrOutputParser()

def generate_manifest(finding: dict, fixed_version: str) -> dict:
    image_name = finding.get("affected_asset", finding.get("image", "unknown"))

    result_yaml = chain.invoke({
        "image_name": image_name,
        "fixed_version": fixed_version
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
        if new_version == fixed_version:
            version_updated = True
            matches_fixed_version = True

    return {
        "manifest": result_yaml,
        "is_valid_yaml": is_valid_yaml,
        "version_updated": version_updated,
        "matches_fixed_version": matches_fixed_version
    }