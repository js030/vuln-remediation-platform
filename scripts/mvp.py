from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

def main():
    finding = scan_image("nginx:1.14.0")
    print(f"[DISCOVERY] {finding['title']} ({finding['severity']})")

    print("[AGENT] Generating corrected manifest via LangChain...")
    manifest_yaml = generate_manifest(finding)

    print("[OUTPUT]")
    print(manifest_yaml)

    with open("manifests/remediated/corrected-deployment.yaml", "w") as f:
        f.write(manifest_yaml)

    print("[SAVED] manifests/remediated/corrected-deployment.yaml")

if __name__ == "__main__":
    main()