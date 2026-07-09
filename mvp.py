from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_remediation

def main():
    finding = scan_image("nginx:1.14.0")
    print(f"[DISCOVERY]{finding['title']} ({finding['severity']})")

    context = {"owner": "team alpha", "criticality": "high", "environment": "mock-production"}
    print(f"[CONTEXT]{context}")

    proposal = generate_remediation(finding, context)
    print(f"[REASONING] Risk: {proposal['risk_score']}/10 - {proposal['proposed_action']}")
    print(f"[REASONING] {proposal['reasoning']}")

    approved = input("Approve (y/n): ")
    if approved.lower() != "y":
        print("[APPROVAL] Rejected.")
        return
    
    print(f"[EXECUTION] Simulating: {proposal['proposed_action']}")
    
if __name__ == "__main__":
    main()