import re
import yaml
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatOllama(model="llama3.2", temperature=0)

manifest_prompt = PromptTemplate(
    input_variables=["original_manifest", "fixed_version"],
    template="""You are a strict configuration generator with no creative freedom.
Your only task is to update the 'image' field in the provided Kubernetes manifest.

ORIGINAL MANIFEST:
{original_manifest}

STRUCTURAL REQUIREMENTS:
1. Find the 'image:' key and replace its tag exactly with: {fixed_version}
2. Do absolutely not change the deployment name, any other values, keys, indentation, or formatting.
3. Do not add any explanations, markdown blocks, or comments.
4. Return exclusively the raw YAML manifest.
"""
)

chain = manifest_prompt | llm | StrOutputParser()
def generate_manifest(finding: dict, fixed_version: str, original_manifest: str) -> dict:
    result_yaml = chain.invoke({
        "original_manifest": original_manifest,
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