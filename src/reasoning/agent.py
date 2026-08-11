from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import PromptTemplate
from langchain_ollama import ChatOllama


llm = ChatOllama(
    model="llama3.2",
    temperature=0,
)

pr_prompt = PromptTemplate(
    input_variables=[
        "workload_kind",
        "workload_name",
        "namespace",
        "container_name",
        "original_image",
        "target_image",
        "policy_owner",
        "resolved_cves",
        "remaining_cves",
        "new_critical_cves",
    ],
    template="""
You are a Kubernetes security remediation assistant.

Create a concise Pull Request description in Markdown.

Requirements:
- The target image was selected from a team-approved image policy.
- Do not claim that the update is risk-free.
- State that human review is required before merge.
- Do not invent CVE IDs or scan results.

Workload:
- Kind: {workload_kind}
- Name: {workload_name}
- Namespace: {namespace}
- Container: {container_name}

Image update:
- Original image: {original_image}
- Team-approved target image: {target_image}
- Policy owner: {policy_owner}

Trivy comparison:
- Resolved relevant CVEs: {resolved_cves}
- Remaining relevant CVEs: {remaining_cves}
- New critical CVEs: {new_critical_cves}

Return Markdown only.
""",
)

chain = pr_prompt | llm | StrOutputParser()


def fallback_pr_description(
    workload_kind: str,
    workload_name: str,
    namespace: str,
    container_name: str,
    original_image: str,
    target_image: str,
    policy_owner: str,
    resolved_cves: list[str],
    remaining_cves: list[str],
    new_critical_cves: list[str],
) -> str:
    """Create deterministic PR text when Ollama is unavailable."""
    resolved_text = ", ".join(resolved_cves) if resolved_cves else "none"
    remaining_text = ", ".join(remaining_cves) if remaining_cves else "none"
    critical_text = (
        ", ".join(new_critical_cves)
        if new_critical_cves
        else "none"
    )

    return f"""## Automated Container Image Remediation

### Workload
- Kind: `{workload_kind}`
- Name: `{workload_name}`
- Namespace: `{namespace}`
- Container: `{container_name}`

### Image update
- Original image: `{original_image}`
- Team-approved target image: `{target_image}`
- Policy owner: `{policy_owner}`

### Trivy verification
- Resolved relevant CVEs: `{resolved_text}`
- Remaining relevant CVEs: `{remaining_text}`
- New critical CVEs: `{critical_text}`

The target was selected from the team-approved image baseline policy.
Human review is required before merge.
"""


def generate_pr_description(
    workload_kind: str,
    workload_name: str,
    namespace: str,
    container_name: str,
    original_image: str,
    target_image: str,
    policy_owner: str,
    resolved_cves: list[str],
    remaining_cves: list[str],
    new_critical_cves: list[str],
) -> str:
    """
    Generate a PR description using Ollama.

    If Ollama is not running or the model fails, the pipeline continues with
    a deterministic fallback text.
    """
    try:
        return chain.invoke(
            {
                "workload_kind": workload_kind,
                "workload_name": workload_name,
                "namespace": namespace,
                "container_name": container_name,
                "original_image": original_image,
                "target_image": target_image,
                "policy_owner": policy_owner,
                "resolved_cves": (
                    ", ".join(resolved_cves)
                    if resolved_cves
                    else "none"
                ),
                "remaining_cves": (
                    ", ".join(remaining_cves)
                    if remaining_cves
                    else "none"
                ),
                "new_critical_cves": (
                    ", ".join(new_critical_cves)
                    if new_critical_cves
                    else "none"
                ),
            }
        )
    except Exception:
        return fallback_pr_description(
            workload_kind=workload_kind,
            workload_name=workload_name,
            namespace=namespace,
            container_name=container_name,
            original_image=original_image,
            target_image=target_image,
            policy_owner=policy_owner,
            resolved_cves=resolved_cves,
            remaining_cves=remaining_cves,
            new_critical_cves=new_critical_cves,
        )
