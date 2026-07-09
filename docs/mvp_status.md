flowchart LR
    A[Discovery<br/>Trivy Scan] -->|✅ Done| B[Context<br/>Mock Data]
    B -->|✅ Done| C[Reasoning<br/>LLM Agent]
    C -->|🟡 Stub / Placeholder| D[Approval<br/>Human-in-the-loop]
    D -->|✅ Done| E[Execution<br/>Simulated]
    E -->|⬜ Not yet real| F[Real Cluster<br/>Change]

    style A fill:#90EE90
    style B fill:#90EE90
    style C fill:#FFD700
    style D fill:#90EE90
    style E fill:#90EE90
    style F fill:#D3D3D3