import yaml

from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate


llm = ChatOllama(model="llama3.2", temperature=0)

manifest_prompt = PromptTemplate(
    input_variables=[
        "original_manifest",
        "workload_kind",
        "workload_name",
        "container_type",
        "container_name",
        "original_image",
        "target_image",
    ],
    template="""You are a strict Kubernetes configuration remediation agent.

Your task is to update exactly one container image in the supplied Kubernetes
YAML manifest.

TARGET WORKLOAD:
- Kind: {workload_kind}
- Name: {workload_name}

TARGET CONTAINER:
- Container group: {container_type}
- Container name: {container_name}
- Current image: {original_image}
- Required replacement image: {target_image}

ORIGINAL MANIFEST:
{original_manifest}

MANDATORY RULES:
1. Update only the image field of the target container named "{container_name}".
2. Replace "{original_image}" exactly with "{target_image}".
3. Do not modify any other image fields.
4. Do not modify metadata, labels, selectors, replicas, ports, resources,
   environment variables, or workload structure.
5. Preserve the workload kind and workload name.
6. Return only raw YAML. Do not return Markdown, explanations, comments,
   or code fences.
""",
)

chain = manifest_prompt | llm | StrOutputParser()


def generate_manifest(
    finding: dict,
    original_manifest: str,
    workload_kind: str,
    workload_name: str,
    container_type: str,
    container_name: str,
    original_image: str,
    target_image: str,
) -> dict:
    """Generate a Kubernetes manifest remediation proposal through the LLM."""
    try:
        result_yaml = chain.invoke(
            {
                "original_manifest": original_manifest,
                "workload_kind": workload_kind,
                "workload_name": workload_name,
                "container_type": container_type,
                "container_name": container_name,
                "original_image": original_image,
                "target_image": target_image,
            }
        )
    except Exception as error:
        return {
            "manifest": None,
            "is_valid_yaml": False,
            "version_updated": False,
            "matches_target_image": False,
            "error": str(error),
        }

    try:
        parsed = yaml.safe_load(result_yaml)
        is_valid_yaml = parsed is not None
    except yaml.YAMLError:
        is_valid_yaml = False

    matches_target_image = target_image in result_yaml

    return {
        "manifest": result_yaml,
        "is_valid_yaml": is_valid_yaml,
        "version_updated": matches_target_image,
        "matches_target_image": matches_target_image,
    }
