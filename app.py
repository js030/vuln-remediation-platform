import streamlit as st
import csv
import os
import time
from datetime import datetime
from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest

st.set_page_config(
    page_title="Vulnerability Remediation Platform",
    layout="wide",
    initial_sidebar_state="expanded"
)

LOG_FILE = "evaluation_log.csv"

# ---------- Sidebar: Configuration ----------
with st.sidebar:
    st.header("Configuration")
    st.markdown("**LLM Provider:** Ollama (llama3.2)")
    st.markdown("**Scanner:** Trivy")
    st.divider()

    if "images" not in st.session_state:
        st.session_state["images"] = [
            "nginx:1.14.0",
            "nginx:1.16.0",
            "httpd:2.4.54"
        ]

    st.subheader("Target Images")
    for img in st.session_state["images"]:
        st.text(f"• {img}")

    new_image = st.text_input("Add image", placeholder="e.g. redis:5.0.0")
    if st.button("Add", use_container_width=True) and new_image:
        st.session_state["images"].append(new_image)
        st.rerun()

    st.divider()
    if st.button("Clear All Results", use_container_width=True):
        st.session_state["results"] = []
        st.rerun()

# ---------- Main Header ----------
st.title("Vulnerability Remediation Platform")
st.markdown(
    "Automated vulnerability detection and AI-assisted remediation for "
    "containerized workloads. Every proposed change requires manual approval "
    "before being written to disk."
)
st.divider()

# ---------- Scan Trigger ----------
selected_images = st.multiselect(
    "Select images to process",
    options=st.session_state["images"],
    default=st.session_state["images"]
)

run_scan = st.button("Run Scan", type="primary")

if "results" not in st.session_state:
    st.session_state["results"] = []

if run_scan:
    progress = st.progress(0, text="Starting...")

    for idx, image_name in enumerate(selected_images):
        entry = {"image": image_name, "timestamp": datetime.now().isoformat()}
        progress.progress(
            idx / len(selected_images),
            text=f"Scanning {image_name}..."
        )

        start_time = time.time()
        try:
            finding = scan_image(image_name)
            entry["cve_id"] = finding["id"]
            entry["severity"] = finding["severity"]
        except Exception as e:
            entry["error"] = f"Discovery failed: {e}"
            entry["yaml_valid"] = False
            st.session_state["results"].append(entry)
            continue

        progress.progress(
            (idx + 0.5) / len(selected_images),
            text=f"Generating manifest for {image_name}..."
        )
        try:
            manifest = generate_manifest(finding)
            entry["manifest"] = manifest
            entry["latency_seconds"] = round(time.time() - start_time, 2)
            entry["yaml_valid"] = True
        except Exception as e:
            entry["error"] = f"Agent failed: {e}"
            entry["yaml_valid"] = False

        st.session_state["results"].append(entry)

    progress.progress(1.0, text="Complete")
    time.sleep(0.3)
    progress.empty()

# ---------- Performance Dashboard ----------
if st.session_state["results"]:
    results = st.session_state["results"]
    total = len(results)
    valid_yaml = sum(1 for e in results if e.get("yaml_valid"))
    approved = sum(1 for e in results if e.get("decision") == "approved")
    rejected = sum(1 for e in results if e.get("decision") == "rejected")
    latencies = [e.get("latency_seconds") for e in results if e.get("latency_seconds")]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0

    st.subheader("Agent Performance Overview")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Scans", total)
    m2.metric("Valid YAML", f"{valid_yaml}/{total}")
    m3.metric("Approved", approved)
    m4.metric("Rejected", rejected)
    m5.metric("Avg. Latency", f"{avg_latency}s")
    st.divider()

# ---------- Results List ----------
if st.session_state["results"]:
    st.subheader("Findings & Proposed Remediations")

    for i, entry in enumerate(st.session_state["results"]):
        status_icon = "⚠️" if "error" in entry else "🔍"

        with st.container(border=True):
            header_col, meta_col = st.columns([3, 2])
            header_col.markdown(f"**{status_icon} {entry['image']}**")

            if "error" in entry:
                st.error(entry["error"])
                continue

            meta_col.markdown(
                f"`{entry.get('cve_id', 'N/A')}` · "
                f"Severity: **{entry.get('severity', 'N/A')}** · "
                f"{entry.get('latency_seconds', 'N/A')}s"
            )

            with st.expander("View generated manifest"):
                st.code(entry.get("manifest", ""), language="yaml")

            decision = entry.get("decision")
            if decision == "approved":
                st.success("Approved — written to manifests/remediated/")
            elif decision == "rejected":
                st.warning("Rejected — no changes written")
            else:
                approve_col, reject_col, _ = st.columns([1, 1, 4])
                if approve_col.button("Approve", key=f"approve_{i}"):
                    filename = f"manifests/remediated/{entry['image'].replace(':', '_')}_{i}.yaml"
                    os.makedirs("manifests/remediated", exist_ok=True)
                    with open(filename, "w") as f:
                        f.write(entry["manifest"])
                    entry["decision"] = "approved"
                    st.rerun()
                if reject_col.button("Reject", key=f"reject_{i}"):
                    entry["decision"] = "rejected"
                    st.rerun()

    st.divider()
    if st.button("Export Evaluation Log"):
        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "image", "cve_id", "severity",
                "latency_seconds", "yaml_valid", "decision"
            ])
            if not file_exists:
                writer.writeheader()
            for entry in st.session_state["results"]:
                writer.writerow({
                    "timestamp": entry.get("timestamp"),
                    "image": entry.get("image"),
                    "cve_id": entry.get("cve_id", ""),
                    "severity": entry.get("severity", ""),
                    "latency_seconds": entry.get("latency_seconds", ""),
                    "yaml_valid": entry.get("yaml_valid", ""),
                    "decision": entry.get("decision", "pending")
                })
        st.success(f"Log exported to {LOG_FILE}")