import streamlit as st
import streamlit.components.v1 as components
import csv
import os
import time
import sys
import difflib
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_manifest
from scripts.batch_test import run_batch_test


LOG_FILE = "logs/evaluation_log.csv"
BATCH_LOG_FILE = "logs/batch_evaluation_log.csv"

st.set_page_config(
    page_title="Vuln-Remediation",
    layout="wide",
    initial_sidebar_state="expanded"
)

LOG_FILE = "evaluation_log.csv"
BATCH_LOG_FILE = "batch_evaluation_log.csv"

def get_base_manifest(image_name):
    app_name = image_name.split(':')[0]
    return f"""apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {app_name}\nspec:\n  replicas: 2\n  selector:\n    matchLabels:\n      app: {app_name}\n  template:\n    metadata:\n      labels:\n        app: {app_name}\n    spec:\n      containers:\n      - name: {app_name}\n        image: {image_name}"""

def render_diff(base_text, new_text):
    diff = difflib.HtmlDiff().make_file(base_text.splitlines(), new_text.splitlines(), context=True, numlines=3)
    custom_css = """
    <style type="text/css">
        table.diff {width: 100%; font-family: monospace; font-size: 14px;}
        .diff_add {background-color: #d4edda; color: #155724;}
        .diff_sub {background-color: #f8d7da; color: #721c24;}
        .diff_header {background-color: #e9ecef;}
    </style>
    """
    return diff.replace('<style type="text/css">', custom_css)

def process_image(image_name):
    entry = {"image": image_name, "timestamp": datetime.now().isoformat()}
    start_time = time.time()
    try:
        finding = scan_image(image_name)
        entry["cve_id"] = finding["id"]
        entry["type"] = finding.get("type", "cve")
        entry["severity"] = finding["severity"]
        
        agent_result = generate_manifest(finding)
        entry["manifest"] = agent_result["manifest"]
        entry["yaml_valid"] = agent_result["is_valid_yaml"]
        entry["version_updated"] = agent_result["version_updated"]
        entry["matches_fixed_version"] = agent_result["matches_fixed_version"]
        entry["latency_seconds"] = round(time.time() - start_time, 2)
    except Exception as e:
        entry["error"] = str(e)
        entry["yaml_valid"] = False
    return entry

with st.sidebar:
    st.subheader("System Configuration")
    st.markdown("**LLM Engine:** Ollama (llama3.2)\n\n**Scanner:** Trivy")
    st.divider()

    if "images" not in st.session_state:
        st.session_state["images"] = ["nginx:1.14.0", "nginx:1.16.0", "httpd:2.4.54"]

    st.subheader("Target Images")
    for img in st.session_state["images"]:
        st.code(img, language="text")

    with st.form("add_image_form", clear_on_submit=True):
        new_image = st.text_input("Add new image", placeholder="redis:5.0.0")
        submitted = st.form_submit_button("Add", width="stretch")
        if submitted and new_image:
            st.session_state["images"].append(new_image)
            st.rerun()

    st.divider()
    if st.button("Clear Live Scan Results", width="stretch"):
        st.session_state["results"] = []
        st.rerun()

st.title("Vulnerability Remediation Platform")
st.markdown("Automated vulnerability detection and AI-assisted remediation. Proposed manifest changes require manual approval before being written to disk.")

tab_live, tab_batch = st.tabs(["Live Scan & Approval", "Batch Evaluation Dashboard"])

with tab_live:
    col_select, col_btn = st.columns([4, 1])
    with col_select:
        selected_images = st.multiselect(
            "Select images to scan",
            options=st.session_state["images"],
            default=st.session_state["images"]
        )
    with col_btn:
        st.write("")
        run_scan = st.button("Run Async Scan", type="primary", width="stretch")

    if "results" not in st.session_state:
        st.session_state["results"] = []

    if run_scan:
        with st.status("Running asynchronous scans and reasoning...", expanded=True) as status:
            st.session_state["results"] = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(process_image, img): img for img in selected_images}
                for future in as_completed(futures):
                    st.session_state["results"].append(future.result())
            status.update(label="Parallel processing complete", state="complete", expanded=False)

    if st.session_state["results"]:
        for i, entry in enumerate(st.session_state["results"]):
            with st.container(border=True):
                col_header, col_meta = st.columns([2, 1])
                col_header.markdown(f"#### {entry['image']}")
                
                if "error" in entry:
                    st.error(f"Error processing {entry['image']}: {entry['error']}")
                    continue

                col_meta.markdown(
                    f"**ID:** `{entry.get('cve_id', 'N/A')}` | "
                    f"**Type:** `{entry.get('type', 'N/A')}` | "
                    f"**Severity:** `{entry.get('severity', 'N/A')}` | "
                    f"**Latency:** `{entry.get('latency_seconds', 'N/A')}s`"
                )

                st.caption("Visueller Diff-Vergleich (Originalstruktur vs. KI-Vorschlag)")
                base_manifest_str = get_base_manifest(entry['image'])
                new_manifest_str = entry.get("manifest", "")
                
                html_diff = render_diff(base_manifest_str, new_manifest_str)
                components.html(html_diff, height=300, scrolling=True)

                if not entry.get("yaml_valid"):
                    st.error("Syntax Error: Generated YAML is invalid.")

                decision = entry.get("decision")
                if decision == "approved":
                    st.info("Status: Approved and saved.")
                elif decision == "rejected":
                    st.info(f"Status: Rejected. Reason: {entry.get('reject_reason')}")
                else:
                    col_act1, col_act2, col_act3 = st.columns([1, 1, 2])
                    if col_act1.button("Approve", key=f"approve_{i}", type="primary"):
                        filename = f"manifests/remediated/{entry['image'].replace(':', '_')}_{i}.yaml"
                        os.makedirs("manifests/remediated", exist_ok=True)
                        with open(filename, "w") as f:
                            f.write(entry["manifest"])
                        entry["decision"] = "approved"
                        st.toast(f"Manifest for {entry['image']} saved.")
                        st.rerun()
                    
                    reject_reason = col_act3.selectbox(
                        "Rejection Reason", 
                        ["Invalid YAML Syntax", "Version Downgrade / No Change", "Hallucinated Fields", "Unwanted Structural Change"], 
                        key=f"reason_{i}",
                        label_visibility="collapsed"
                    )
                    
                    if col_act2.button("Reject", key=f"reject_{i}"):
                        entry["decision"] = "rejected"
                        entry["reject_reason"] = reject_reason
                        st.rerun()

        if st.button("Export Session Log", width="stretch"):
            file_exists = os.path.isfile(LOG_FILE)
            with open(LOG_FILE, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "image", "cve_id", "severity", "type",
                    "latency_seconds", "yaml_valid", "version_updated", "matches_fixed_version", "decision", "reject_reason"
                ])
                if not file_exists:
                    writer.writeheader()
                for entry in st.session_state["results"]:
                    if "error" not in entry:
                        writer.writerow({k: entry.get(k, "") for k in writer.fieldnames})
            st.toast(f"Log successfully exported to {LOG_FILE}.")

with tab_batch:
    col_batch_run, col_batch_reload, _ = st.columns([2, 2, 4])
    if col_batch_run.button("Run Batch Evaluation", type="primary", width="stretch"):
        with st.spinner("Running Batch Evaluation in the background..."):
            run_batch_test()
        st.toast("Batch Evaluation complete.")
        st.rerun()

    if col_batch_reload.button("Reload Data", width="stretch"):
        st.rerun()

    st.divider()

    if os.path.isfile(BATCH_LOG_FILE):
        df = pd.read_csv(BATCH_LOG_FILE)
        
        for col in ["yaml_valid", "version_updated", "matches_fixed_version"]:
            if col in df.columns:
                df[col] = df[col].astype(str).str.lower().map({"true": True, "false": False}).fillna(False)
        if "latency_seconds" in df.columns:
            df["latency_seconds"] = pd.to_numeric(df["latency_seconds"], errors="coerce")
        
        filter_image = st.selectbox("Filter by Image", ["All"] + list(df.get("image", pd.Series(dtype=str)).unique()))
        if filter_image != "All":
            df = df[df["image"] == filter_image]

        total_runs = len(df)
        syntax_success = df["yaml_valid"].mean() * 100 if "yaml_valid" in df.columns and total_runs else 0
        semantic_success = df["version_updated"].mean() * 100 if "version_updated" in df.columns and total_runs else 0
        exact_match = df["matches_fixed_version"].mean() * 100 if "matches_fixed_version" in df.columns and total_runs else 0
        avg_latency = df["latency_seconds"].mean() if "latency_seconds" in df.columns and not df["latency_seconds"].isna().all() else 0

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Runs", total_runs)
        m2.metric("Syntax Success", f"{syntax_success:.1f}%")
        m3.metric("Version Upgrade", f"{semantic_success:.1f}%")
        m4.metric("Exact Match", f"{exact_match:.1f}%")
        m5.metric("Avg. Latency", f"{avg_latency:.2f}s")

        st.dataframe(
            df,
            width="stretch",
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                "image": "Image",
                "cve_id": "ID (CVE/Misconfig)",
                "severity": "Severity",
                "type": "Type",
                "yaml_valid": st.column_config.CheckboxColumn("Valid YAML"),
                "version_updated": st.column_config.CheckboxColumn("Version Up"),
                "matches_fixed_version": st.column_config.CheckboxColumn("Exact Match"),
                "latency_seconds": st.column_config.NumberColumn("Latency (s)", format="%.2f")
            },
            hide_index=True
        )
    else:
        st.info(f"No batch data found. Please run an evaluation to generate '{BATCH_LOG_FILE}'.")