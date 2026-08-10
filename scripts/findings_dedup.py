import json
import os
from datetime import datetime

FINDINGS_FILE = "logs/findings_history.json"

def load_previous_findings():
    """Lädt Findings aus dem letzten Scan."""
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE, "r") as f:
            return json.load(f)
    return {"timestamp": None, "findings": []}

def save_findings(findings):
    """Speichert aktuelle Findings für nächsten Scan."""
    os.makedirs("logs", exist_ok=True)
    with open(FINDINGS_FILE, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "findings": findings
        }, f, indent=2)

def has_new_findings(current_findings, previous_findings):
    """Prüft, ob neue Findings seit letztem Scan."""
    prev_set = set(tuple(sorted(f.items())) for f in previous_findings.get("findings", []))
    curr_set = set(tuple(sorted(f.items())) for f in current_findings)
    
    new_findings = curr_set - prev_set
    return len(new_findings) > 0, new_findings

def should_create_pr(current_findings):
    """Entscheidungslogik: PR nur bei neuen Findings."""
    prev = load_previous_findings()
    has_new, new = has_new_findings(current_findings, prev)
    
    if has_new:
        print(f"[NEW] {len(new)} neue Findings → PR wird erstellt")
        save_findings(current_findings)
        return True
    else:
        print(f"[SKIP] Keine neuen Findings seit letztem Scan")
        return False
