# Garudatva v3 — APK Behaviour Analyzer with C2 Detection

## **CIDECODE 2026 — Team CyberHawks**


A forensic-grade Android malware analysis platform built for Indian law enforcement. Garudatva accepts an APK file, runs a multi-stage analysis pipeline, and produces a digitally-signed, court-admissible PDF report compliant with the IT Act 2000, BNSS 2023, and BSA 2023.

---

## What Makes This Different

Most APK analysis tools tell you an app is malicious. Garudatva tells you which criminal syndicate built it, links it to other cases across jurisdictions, and gives an investigating officer a document they can walk into court with.

Specific capabilities no comparable tool provides:

- **Cross-district syndicate detection** — Neo4j graph database links IOCs (developer certificates, UPI VPAs, C2 domains) across unrelated cases to identify coordinated malware campaigns
- **BNSS Section 176(3) compliance** — built-in seizure video ingestion and exhibit generation, mandated by the 2023 code for offences carrying 7+ year sentences
- **IT Act Section 65B certificate auto-generation** — digital evidence is inadmissible in Indian courts without this; Garudatva generates it automatically
- **India-specific ML classifier** — trained on UPI fraud patterns, Aadhaar harvesting APKs, banking trojans targeting Indian PSBs, and fake loan apps; not a repurposed Western dataset
- **Air-gap capable** — full analysis runs with zero internet connectivity using local Ollama inference, designed for field deployment on police workstations

---

## Architecture

```
Frontend (React)
      |
      | POST /api/v1/analyze  (multipart APK upload)
      v
FastAPI + Uvicorn  (main.py)
      |
      v
Pipeline Orchestrator  (core/pipeline.py)
      |
      |-- Stage 1: Static Triage          (always runs, ~60s)
      |-- Stage 2: Dynamic Sandbox        (if risk score >= 65, ~10min)
      |-- Stage 3: Cloud C2 Detection     (if dynamic ran)
      |-- Stage 4: Neo4j Graph Ingestion  (always)
      |-- Stage 5: LLM Narrative          (Ollama, local)
      |-- Stage 6: PDF Generation         (ReportLab + pyhanko)
      |
      v
Signed PDF report  +  JSON result  +  Custody chain log
```

---

## Pipeline Stages

### Stage 1 — Static Analysis

Performed on every APK regardless of risk level. No execution required.

- APK unpacked as ZIP; manifest, DEX files, native libraries, and certificate extracted
- Manifest parser checks for dangerous permissions, debuggable flag, cleartext traffic, hidden launcher icon
- Permission scorer evaluates 23 dangerous permissions and 4 toxic combination patterns (e.g. READ\_SMS + BIND\_ACCESSIBILITY\_SERVICE + INTERNET)
- DEX analyzer extracts class names, API calls, hardcoded strings (URLs, IPs, UPI VPAs, phone numbers)
- YARA scanner runs 6 rule files: UPI fraud, banking trojans, fake loan apps, Aadhaar harvesting, RAT indicators, C2 infrastructure
- India patterns engine checks 47 patterns across 7 categories: UPI fraud, SMS OTP theft, Aadhaar/PAN harvesting, fake loan, overlay attacks, location tracking, keylogging
- Certificate parser checks for debug certificates, expiry, self-signing, and weak keys
- Native library analyzer scans .so files for anti-analysis strings (Frida, Magisk, emulator detection) and dangerous syscalls (ptrace, execve)
- Random Forest classifier (87 features, trained on Drebin + AMD + CIC-AndMal2017) outputs malware probability
- Risk score 0-100 mapped to four tiers: BENIGN (0-29), SUSPICIOUS (30-64), HIGH RISK (65-84), CRITICAL (85-100)

### Stage 2 — Dynamic Sandbox

Runs when static risk score is >= 65, or when static analysis itself
degraded (packed/obfuscated APK) regardless of score — see
`core/pipeline.py`. Requires a real Android emulator: run
`backend/scripts/setup_android_sandbox.sh` once per host to provision the
SDK, AVD, and a matching `frida-server` build. That script's first check
is hardware virtualization (`/dev/kvm` on Linux, Hypervisor.framework on
macOS) — without it the emulator cannot boot at all, which is a host/VM
configuration issue, not something the application can work around.
Verify readiness any time with:
`python3 -c "from core.dynamic.sandbox_manager import check_sandbox_prerequisites as c; print(c() or 'READY')"`

- Android Virtual Device booted from clean snapshot via ADB
- APK installed and launched
- Frida hooks intercept: crypto key material, SMS sends, clipboard reads, accessibility events, HTTP/S requests with decrypted payloads
- MonkeyRunner generates automated UI interaction (taps, swipes, text input) for 120 seconds to trigger deferred malicious behaviour
- strace records all system calls for 120 seconds
- tshark captures network traffic on the AVD bridge interface
- Memory dumped at peak activity for string extraction
- Emulator restored to clean snapshot on completion

### Stage 3 — Cloud C2 Detection

- All IOCs from static and dynamic stages classified against cloud provider ASN ranges (AWS, GCP, Azure, Cloudflare, Akamai, Firebase)
- Tunnel service detection: ngrok, Cloudflare Tunnel, serveo, localtunnel, pagekite — static string match in DEX catches these even after the session has expired
- DGA detection: Shannon entropy + n-gram analysis on domain labels; entropy > 3.8 with subdomain length > 12 flagged
- JA4 TLS fingerprinting on captured traffic
- JARM active probing of live C2 servers; hash matched against database of Cobalt Strike, Metasploit, AsyncRAT, njRAT signatures

### Stage 4 — Neo4j Graph

- IOCs (IPs, domains, UPI VPAs, phone numbers, certificate hashes, package names) stored as typed nodes
- Edges represent observed relationships: same\_developer, same\_c2, same\_upi\_vpa, same\_cert\_hash
- Syndicate linker queries for connected components across all cases in the database
- Cross-district linkage: two APKs uploaded by different officers in different cities can be automatically linked if they share infrastructure

### Stage 5 — LLM Narrative

- Ollama serves Qwen2.5-7B-Instruct (Q4\_K\_M quantisation) locally; no data leaves the workstation
- Structured analysis results passed as context; model writes the Observations and Findings section in plain English suitable for a court document
- Output validated by narrative\_validator.py before inclusion in PDF
- Factual content (IOCs, risk scores, YARA matches) sourced from deterministic stages; LLM does not make evidentiary claims

### Stage 6 — PDF Report

- ReportLab assembles the full forensic PDF with structured sections: case metadata, executive summary, risk score with SHAP feature attribution, IOC tables, YARA evidence, India pattern matches, network artefacts, custody chain, exhibits
- BSA Section 63 custody chain appended: SHA256 hash, timestamp, and actor logged for every file and action in the pipeline
- BNSS Section 176(3) seizure video linked as Exhibit A with mandatory fields (GPS coordinates, officer badge, witnesses)
- IT Act Section 65B certificate generated
- pyhanko applies a digital signature using the analyst's certificate

---

## Repository Structure

```
garudatva/
  backend/
    backend/
      main.py                  # FastAPI application entry point
      config.py                # All settings and environment variables
      requirements.txt         # Python dependencies
      api/                     # HTTP route handlers
        analysis.py            # APK upload, job status, results
        reports.py             # PDF download
        graph.py               # IOC graph queries
        jarm.py                # JARM probing and QR air-gap bridge
        evidence.py            # Evidence locker management
      core/
        pipeline.py            # Pipeline orchestrator
        custody_chain.py       # BSA 63 tamper-evident log
        static/                # Stage 1 modules (8 files)
        dynamic/               # Stage 2 modules (7 files + 6 Frida JS hooks)
        ja4/                   # JA4 TLS fingerprinting
        jarm/                  # JARM fingerprinting and database
        graph/                 # Neo4j client and queries
        ai/                    # Ollama client and prompt builder
        report/                # PDF builder, signer, exhibit templates
        evidence/              # Evidence locker and video ingestor
      models/                  # Pydantic data models
        analysis.py            # AnalysisJob, PipelineStage, RiskTier
        ioc.py                 # IOC, NetworkArtifact, CloudProvider
        report.py              # ReportSection, ExhibitReference
        risk_score.py          # RiskScore with SHAP fields
        evidence.py            # EvidenceItem, VideoEvidence, LockerManifest
      ml/
        trainer.py             # Random Forest training script
        feature_extractor.py   # Batch APK feature extraction (99 features)
        evaluator.py           # AUC, FPR, SHAP evaluation report
        models/                # Trained model files (generated, not committed)
        datasets/              # Training data (not committed, see README)
      utils/
        hasher.py              # SHA256, MD5, SHA1
        logger.py              # Structured logging
        ram_monitor.py         # RAM guardrails (warn at 6GB, halt at 7.5GB)
  signatures/
    jarm_malicious_hashes.json
    known_c2_iocs.json
    ja4_fingerprints.json
    india_fraud_patterns.json
    toxic_permissions.json
  yara-rules/
    upi_fraud.yar
    banking_trojans.yar
    fake_loan_apps.yar
    aadhaar_harvesting.yar
    rat_indicators.yar
    c2_infrastructure.yar
```

---

## Technology Stack

| Component | Technology | Version |
|---|---|---|
| Web framework | FastAPI + Uvicorn | 0.115.5 / 0.32.1 |
| Data validation | Pydantic v2 | 2.10.3 |
| APK analysis | androguard | 3.4.0 |
| Pattern matching | yara-python | 4.5.1 |
| Machine learning | scikit-learn (Random Forest) | 1.5.2 |
| ML explainability | SHAP | 0.46.0 |
| Graph database | Neo4j | 5.20 (Docker) |
| Cache / job queue | Redis | 7 (Docker) |
| LLM inference | Ollama + Qwen2.5-7B-Instruct | local |
| Dynamic instrumentation | Frida | latest |
| PDF generation | ReportLab | 4.2.5 |
| PDF signing | pyhanko | 0.21.1 |
| Async HTTP | httpx | 0.28.1 |
| Numerical computation | NumPy + pandas | 1.26.4 / 2.2.3 |

---

## ML Model

**Algorithm:** Random Forest (100 estimators, balanced class weights)

**Feature vector:** 99 raw features extracted per APK, reduced to 87 by information gain selection

Feature groups:
- 23 dangerous permission flags
- 12 manifest properties (debuggable, cleartext, activity/service/receiver counts, obfuscation score)
- 20 DEX string features (URL count, IP count, crypto class presence, reflection usage, encoded strings)
- 8 certificate features (debug cert, expiry, self-signed, validity duration)
- 10 native library features (suspicious imports, anti-analysis strings, entropy)
- 16 behavioural heuristics (India-specific: UPI strings, bank sender IDs, Aadhaar regex, loan keywords)
- 10 syscall features (populated from dynamic analysis when available)

**Training datasets:**

| Dataset | Samples | Source |
|---|---|---|
| Drebin | 129,013 (5,560 malware + 123,453 benign) | TU Braunschweig — request access |
| AMD (Argus) | 24,650 | arguslab.org — request access |
| CIC-AndMal2017 | 10,854 | University of New Brunswick — direct download |

**Target performance:** AUC >= 0.972, FPR <= 0.03

The trained model file (`ml/models/india_malware_rf.pkl`) is not committed to this repository. Generate it by running `ml/trainer.py` after downloading the datasets to `ml/datasets/`.

---

## Setup and Installation

**Requirements:** Linux (Ubuntu 22.04+ recommended), Python 3.11+, Docker, Android SDK, 8GB+ RAM

### 1. Clone and install

```bash
git clone https://github.com/YOUR_ORG/garudatva.git
cd garudatva/backend

python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Start infrastructure

```bash
docker run -d --name garudatva-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/garudatva \
  neo4j:5.20

docker run -d --name garudatva-redis \
  -p 6379:6379 redis:7-alpine
```

### 3. Install Ollama and pull model

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct-q4_K_M
```

### 4. Configure environment

Create `backend/backend/.env`:

```env
NEO4J_PASSWORD=garudatva
OLLAMA_BASE_URL=http://localhost:11434
AIR_GAP_MODE=false
```

### 5. Run the server

```bash
cd backend/backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API documentation available at `http://localhost:8000/docs`

---

## Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/analyze` | Upload APK and start analysis |
| GET | `/api/v1/status/{job_id}` | Poll pipeline stage progress |
| GET | `/api/v1/result/{job_id}` | Full analysis result as JSON |
| GET | `/api/v1/reports/{job_id}/download` | Download signed PDF report |
| GET | `/api/v1/graph/{job_id}` | IOC graph data for visualisation |
| GET | `/api/v1/graph/syndicate/search` | Cross-case syndicate search |
| POST | `/api/v1/jarm/qr/generate` | Generate QR code for air-gap transfer |
| GET | `/health` | Server health check |

---

## Legal Compliance

| Standard | Coverage |
|---|---|
| IT Act 2000, Section 65B | Certificate auto-generated for every report |
| IT Act 2000, Section 79A | Digital evidence examiner designation field |
| BNSS 2023, Section 176(3) | Seizure video ingestion, GPS, witness fields, exhibit generation |
| BSA 2023, Section 63 | Tamper-evident custody chain with SHA256 at every step |
| ISO/IEC 27037 | Digital evidence acquisition principles applied throughout |

---

## Current Status

| Component | Status |
|---|---|
| All 70 Python files | Syntax verified, zero errors |
| API routers (5) | Complete |
| Pipeline orchestrator | Complete |
| Static analysis modules (8) | Complete |
| Dynamic analysis modules (7) | Complete |
| Frida JS hooks (6) | Complete |
| JA4 / JARM fingerprinting | Complete |
| Neo4j graph layer | Complete |
| LLM narrative engine | Complete |
| PDF report builder | Complete |
| Evidence locker | Complete |
| ML feature extractor | Complete |
| ML evaluator | Complete |
| Pydantic models (5) | Complete |
| Signature JSON files | Seeded |
| YARA rule files | Seeded |
| ML model (.pkl) |  requires dataset download and training run |
| Integration testing |  requires Linux deployment |

---

## Team

CyberHawks — PES University
