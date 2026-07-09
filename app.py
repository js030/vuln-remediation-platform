import  streamlit as st
from src.discovery.trivy_collector import scan_image
from src.reasoning.agent import generate_remediation

st.set_page_config(page_title="Vulnerability Remediation Platform", page_icon=":shield:", layout="wide")
st.title("AI Vulnerability Remediation Platform")

st.subheader("Step 1: Discovery")
if st.button("Scan Image (nginx:1.14.0)"):
    finding = scan_image("nginx:1.14.0")
    st.session_state["finding"] = finding

if "finding" in st.session_state:
    finding = st.session_state["finding"]
    st.success(f"Found: **{finding['title']}**")
    st.write(f"Severity: `{finding['severity']}`")

    st.subheader("Step 2: Context")
    context = {"owner": "team alpha", "criticality": "high", "environment": "mock-production"}
    st.json(context)

    st.subheader("Step 3: Reasoning")
    if st.button("Generate Remediation Proposal"):
        proposal = generate_remediation(finding, context)
        st.session_state["proposal"] = proposal

    if "proposal" in st.session_state:
        proposal = st.session_state["proposal"]
        st.metric("Risk Score", f"{proposal['risk_score']}/10")
        st.write(f"**Proposed Action:** {proposal['proposed_action']}")
        st.info(proposal["reasoning"])

        st.subheader("Step 4: Approval")
        col1, col2 = st.columns(2)
        if col1.button("Approve"):
            st.success(f"[EXECUTION] Simulating: {proposal['proposed_action']}")
        if col2.button("Reject"):
            st.error("Remediation rejected.")