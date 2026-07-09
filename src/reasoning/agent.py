def generate_remediation(finding: dict, context: dict) -> dict:

    return{
        "finding_id": finding["id"],
        "risk_score": 8,
        "action_type": "k8s_patch",
        "proposed_action": "Update image to  a patched version",
        "reasoning": "[STUB] Placeholder reasoning - real LLM call not yet connected",
        "requires_approval": True,
    }
    