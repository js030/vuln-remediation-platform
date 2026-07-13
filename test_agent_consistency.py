from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

test_images = [
    "nginx:1.14.0",      # HTTP/Web-Server-CVEs
    "redis:5.0.0",        # Datenbank/Cache-CVEs
    "python:3.6.0",       # Sprach-Runtime-CVEs
    "node:10.0.0",        # Node.js-CVEs
    "postgres:9.6.0",     # Datenbank-CVEs
    "httpd:2.4.20",       # Apache-CVEs (anderer Fehlertyp als nginx)
]

for image in test_images:
    print(f"\n--- Testing: {image} ---")
    try:
        finding = scan_image(image)
        manifest = generate_manifest(finding)
        print(manifest)
    except Exception as e:
        print(f"[ERROR] {e}")