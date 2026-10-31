# Project PARALLAX

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

![Python 3.13](https://img.shields.io/badge/Python-3.13.14-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Reasoning-Gemini_2.5_Flash-8E75B2?logo=googlegemini&logoColor=white)
![Typecheck](https://img.shields.io/badge/mypy-strict_100%25_pass-brightgreen)
![Code Style](https://img.shields.io/badge/ruff-checked_&_formatted-brightgreen)
![Tests](https://img.shields.io/badge/pytest-8_passed,_1_xfail-brightgreen)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Executive Summary & The Breakthrough Discovery

Modern security teams are adopting autonomous AI defense platforms—combining cloud exposure mapping (**Wiz**), frontier model code analysis (**Gemini**), automated IDE/CLI code patching (**CodeMender**), and machine-speed runtime detection (**Google Security Operations**).

While studying this paradigm from both a **Google Cloud Architect** and **Offensive Security (Red-Team)** perspective, a critical architectural blind spot emerged: **Cross-Layer Remediation Divergence ("Split-Brain AI Patching")**.

When a vulnerability spans both application code and cloud infrastructure, automated remediation often operates in **silos**:
1. **The Code Silo (IDE/CLI Autofix):** An AI coding assistant rapidly patches a Python dataflow bug in the developer's IDE so unit tests and static code scanners turn green.
2. **The Cloud Infrastructure Silo (Terraform / IAM):** Because the IDE patch does not modify the cloud infrastructure repo, over-permissive Non-Human Identity (NHI) Service Account bindings remain wide open in the GCP graph.
3. **The Runtime Telemetry Silo (Google SecOps):** Minor refactoring inside the AI code patch (such as renaming a tool identifier) silently breaks downstream Cloud Audit Log detection signatures—leaving the "patched" system blinder to attack than before.

**Project PARALLAX** is an autonomous adversarial architecture and purple-team verification engine built to detect, prove, and resolve **Split-Brain AI Remediation** across **Python ASTs**, **GCP Terraform IAM Graphs**, and **Google SecOps Detection Rules** using isolated local **Git Worktrees**.

---

## 2. The 4-Step Defense vs. Adversarial Counter-Framework

Project PARALLAX models the offensive counterpart to each pillar of **Google AI Threat Defense** via four specialized subagents orchestrated by a central main thread:

| Google AI Threat Defense Pillar | Adversarial Counter-Step (Attacker Model) | Project PARALLAX Subagent | Technical Verification Mechanism |
| :--- | :--- | :--- | :--- |
| **01 Prepare** (Harden foundation & build live exposure maps via Wiz) | **01 Infiltrate the Trusted Graph** (Abuse Non-Human Identities & transitive IAM paths) | `Subagent 01: Graph Analyzer` (`parallax/graph_analyzer.py`) | Parses GCP Terraform (`hcl2`) into a `networkx.DiGraph` to trace public Cloud Run ingress to project-wide IAM blast radius. |
| **02 Scan** (Multi-AI Gemini code analysis + Wiz runtime context) | **02 Chain Cross-Context Logic Flaws** (Exploit seams between app AST and cloud IAM) | `Subagent 02: Cross-Layer Auditor` (`parallax/cross_layer_auditor.py`) | Combines Python `ast` dataflow inspection with live **Gemini 2.5** reasoning and IAM risk context to flag Confused Deputy bypasses. |
| **03 Remediate** (Shrink fixes from weeks to minutes via CodeMender) | **03 Exploit the Supervision & Patch Gap** (Weaponize symptom-only AI code patches) | `Subagent 03: Worktree Patch Verifier` (`parallax/patch_verifier.py`) | Spins up isolated `git worktree` sandboxes to diff candidate fixes across Code, Terraform, and SecOps rules simultaneously. |
| **04 Monitor** (Machine-speed runtime hunting via Google SecOps) | **04 Blend into Agentic Telemetry** (Evade alerts via schema & tool-signature drift) | `Subagent 04: Telemetry Validator` (`parallax/telemetry_validator.py`) | Audits emitted `AuditEvent` AST structures against SecOps YAML rules (`rules.yaml`) to catch silent detection blind spots. |

---

## 3. System & Target Architecture

### 3.1 Benchmark Target: GCP Cloud Run AI Agent (`benchmark_target/`)

```text
+-----------------------------------------------------------------------------------+
|                        EXTERNAL UNTRUSTED CALLER (HTTPS)                          |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | 1. Bearer Auth + Tool Payload:
                                          |    resource_id = "workspace-doc-notes"
                                          |    use_fallback = True
                                          |    fallback_secret_id = "prod-master-db"
                                          v
+-----------------------------------------------------------------------------------+
| GCP CLOUD RUN v2 SERVICE: "vertex-ops-agent" (ingress = INGRESS_TRAFFIC_ALL)      |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | APPLICATION LAYER: benchmark_target/app/service.py                        |   |
|   | - Enforces verify_caller_auth() upfront                                   |   |
|   | - Checks primary_id.startswith("workspace-doc-")                   [OK]   |   |
|   | - FLAW: Overwrites effective_secret_id = fallback_id without prefix [!]   |   |
|   +-------------------------------------+-------------------------------------+   |
|                                         |                                         |
|                                         | 2. Assumes Non-Human Identity (NHI)     |
|                                         v                                         |
|   +---------------------------------------------------------------------------+   |
|   | GCP SERVICE ACCOUNT: sa-agent-runner@gcp-sg-parallax-sandbox.iam...       |   |
|   +-------------------------------------+-------------------------------------+   |
+-----------------------------------------|-----------------------------------------+
                                          |
            +-----------------------------+-----------------------------+
            |                                                           |
            | 3a. Over-Permissive IAM Binding (main.tf)                 | 3b. Telemetry Emission
            v                                                           v
+-----------------------------------------------+   +-----------------------------------------------+
| GCP INFRASTRUCTURE LAYER (Terraform HCL2)     |   | GOOGLE SECOPS LAYER (secops/rules.yaml)       |
| - google_project_iam_member:                  |   | - Rule SECOPS_GCP_001 & SECOPS_GCP_002        |
|   * roles/secretmanager.secretAccessor [CRIT] |   | - Watches tool_name="read_workspace_context"  |
|   * roles/iam.serviceAccountTokenCreator[HIGH]|   | - BLINDSPOT: If an IDE patch renames          |
| - Allows reading ANY "prod-*" secret across   |   |   tool_name to "..._v2", alerts silently fail!|
|   the entire GCP project!                     |   |                                               |
+-----------------------------------------------+   +-----------------------------------------------+