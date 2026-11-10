# dfirbaboon

> **Open-Source, Cloud-Native, Serverless Digital Forensics & Incident Response (DFIR) Pipeline**  
> Repository: [`https://github.com/awfullyniceguy/dfirbaboon`](https://github.com/awfullyniceguy/dfirbaboon)

**dfirbaboon** is an event-driven, serverless forensic processing pipeline built on AWS (S3, EventBridge, ECS Fargate, AWS Batch on EC2, ECR, and KMS). Designed as an automated cloud-native alternative to traditional monolithic tools like Magnet AXIOM and Autopsy, it scales seamlessly from small artifact drops up to terabyte-scale enterprise disk images.

Dropping any disk image (`.raw`, `.dd`, `.E01`, `.aff`) or standalone forensic artifact (`.evtx`, `.pf`, `.lnk`, binaries) under an incident prefix (`INCXXXXX/<filename>`) in the intake bucket automatically:
1. **Enforces Evidentiary Standards (NIST SP 800-86, OSAC, FRE 1006):** Applies S3 Object Lock in **`COMPLIANCE`** mode, places an explicit **S3 Legal Hold** on raw evidence, sets strict local read-only permissions (`chmod 0400`), and verifies cryptographic digests against collector acquisition hashes.
2. **Routes Intelligently by Evidence Size:** Objects **$\le$ 50 GiB** run on serverless **ECS Fargate** workers (200 GiB ephemeral disk); objects **$>$ 50 GiB** route automatically to **AWS Batch on EC2** (`i4i.2xlarge` with 1.8 TB local NVMe SSD) to avoid storage and memory exhaustion.
3. **Streams & Computes Dual Hashes in Parallel:** Parallel ranged 16 MiB chunks stream through high-speed disk for `SHA-256` and `MD5` calculation without loading multi-gigabyte images into RAM.
4. **Executes Multi-Volume TSK, Carving & YARA in Parallel:** Automatically maps all partitions via `mmls`, runs **The Sleuth Kit (TSK)** and **unallocated space carving (`blkls` + PhotoRec)** concurrently, and performs comprehensive **YARA** rule matching.
5. **Generates Token-Safe AI & Obsidian Markdown Reports:** Produces structured Markdown reports with YAML frontmatter, WikiLinks, and FRE 1006 evidentiary disclaimers alongside raw CSV supertimelines and JSON Chain of Custody manifests.
6. **Supports Controlled Enterprise Landing Zones:** Operates in full self-provisioning mode or a decoupled **Bring-Your-Own (BYO)** model for environments with pre-vended KMS keys, S3 evidence lakes, IAM permissions boundaries, and private VPCs.

---

## Architecture Overview

```text
+---------------------------------------------------------------------------------------------------------------------------------+
|                                                   AWS Cloud (Serverless DFIR)                                                   |
|                                                                                                                                 |
|  +-------------------------------+             S3 Object Created               +---------------------------------------------+  |
|  |       S3 Intake Bucket        | ------------------------------------------> |             Amazon EventBridge              |  |
|  | dfirbaboon-intake-<acct_id>   |      s3://.../INC10492/server.raw           |          dfirbaboon-evidence-drop           |  |
|  | (Lifecycle Expire, SSE-KMS)   |                                             +----------------------+----------------------+  |
|  +---------------+---------------+                                                                    |                         |
|                  |                                                      Size <= 50 GiB                | Size > 50 GiB           |
|                  | (Private via S3 Gateway Endpoint - $0 Data Transfer) +-----------------------------+-------------------------+
|                  |                                                      |                                                       |
|                  |                                                      v ecs:RunTask                           v batch:SubmitJob
|                  |                                        +---------------------------+           +-----------------------------+
|                  |                                        |    ECS Fargate Worker     |           |    AWS Batch (EC2 Worker)   |
|                  +--------------------------------------> |   dfirbaboon-tsk-worker   |           |  dfirbaboon-tsk-worker-large|
|                  |                                        |  4 vCPU | 16 GB RAM       |           |  i4i.2xlarge (8 vCPU, 64GB) |
|                  |                                        |  200 GiB Ephemeral Disk   |           |  1.8 TB Local NVMe SSD      |
|                  |                                        |  Evidence <= 50 GiB       |           |  Evidence 50 GiB - 1+ TB    |
|                  |                                        +-------------+-------------+           +--------------+--------------+
|                  |                                                      |                                        |
|                  |                                                      +-------------------+--------------------+
|                  |                                                                          |
|                  | 1. Parallel Ranged Download (16 MiB chunks)                              |
|                  | 2. Dual SHA-256 + MD5 Pass + Acquisition Hash Verification               |
|                  | 3. Copy to Vault directly as GLACIER_IR (~$0.004/GB-mo) + S3 Legal Hold  |
|                  | 4. Concurrent TSK Multi-Volume + blkls/Carving + YARA                     |
|                  | 5. Incremental S3 Checkpoint Uploads                                     v
|                  |
|                  v
|  +---------------------------------------------------------------------------------------------------------------------------+  |
|  |                           Immutable Incident Vault: dfirbaboon-inc10492-<acct_id> (or Enterprise Lake)                   |  |
|  |                                                                                                                           |  |
|  |  ├── raw_evidence/                                                                                                        |  |
|  |  │   └── server.raw                     (StorageClass: GLACIER_IR, S3 Object Lock COMPLIANCE, S3 Legal Hold: ON)          |  |
|  |  └── analysis/server.raw/                                                                                                |  |
|  |      ├── chain_of_custody.json         (Cryptographic CoC, SBOM, Acquisition Hash Audit & Checkpoints)                     |  |
|  |      ├── timelines/                                                                                                       |  |
|  |      │   └── mactime_supertimeline.csv (Full Multi-Volume TSK Bodyfile Supertimeline)                                     |  |
|  |      ├── carving/                                                                                                         |  |
|  |      │   └── carved_files_inventory.csv(Hashes of all files carved from unallocated space)                               |  |
|  |      └── markdown/                     (Token-Safe LLM/Obsidian Reports with FRE 1006 Disclaimers)                          |  |
|  |          ├── 00_CHAIN_OF_CUSTODY.md                                                                                       |  |
|  |          ├── 01_TSK_FILE_SYSTEM_SUMMARY.md                                                                                |  |
|  |          ├── 02_HIGH_RISK_TIMELINE_ARTIFACTS.md                                                                           |  |
|  |          ├── 03_YARA_AND_ANOMALIES.md                                                                                     |  |
|  |          └── 04_CARVED_FILES_AND_UNALLOCATED.md                                                                           |  |
|  +---------------------------------------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------------------------------------+
```

---

## Evidentiary Standards & Legal Defensibility

`dfirbaboon` is architected to satisfy strict digital forensic evidentiary requirements:

| Standard / Mandate | Pipeline Implementation |
| :--- | :--- |
| **NIST SP 800-86** (Forensic Evidence Integration) | Automated intake hash verification against collector acquisition hashes passed via S3 object metadata (`acquisition-sha256`) or adjacent `manifest.json`. Fails loudly if digests do not match. |
| **OSAC Digital Evidence Guidelines** | Raw evidence is immediately marked read-only locally (`chmod 0400`) upon download. Preserved in S3 with dual cryptographic hashes (`SHA-256` and `MD5`). |
| **S3 Object Lock `COMPLIANCE` Mode** | Dynamic incident vault buckets enforce SEC Rule 17a-4 / FINRA compliant WORM (Write Once, Read Many) retention for 365 days. |
| **S3 Legal Hold** | Explicit `s3:PutObjectLegalHold` (`Status: ON`) is automatically applied to `raw_evidence/<filename>` to prevent deletion even by AWS root users. |
| **ISO 17025 / ASTM E2678 (Tool Provenance)** | Full Software Bill of Materials (SBOM) recorded in `chain_of_custody.json`: container image digest, OS kernel release, tool versions (TSK, YARA, PhotoRec, ExifTool), YARA ruleset SHA-256 hashes, and NTP clock source. |
| **Federal Rule of Evidence 1006 (FRE 1006)** | Standardized evidentiary summary disclaimer embedded into all generated Markdown reports declaring automated extraction methodology from byte-level evidence. |
| **AWS CloudTrail S3 Data Events** | Complete audit trail of every `GetObject`, `PutObject`, and `PutObjectLegalHold` API call captured and archived in a dedicated audit log bucket. |

---

## Dual-Tier Compute & Cost Optimization

| Feature | Small/Medium Images ($\le$ 50 GiB) | Large Server Images ($>$ 50 GiB to 1+ TB) |
| :--- | :--- | :--- |
| **Compute Engine** | **AWS ECS Fargate** | **AWS Batch on EC2** |
| **Instance / Sizing** | Serverless (4 vCPU, 16 GiB RAM) | Dedicated `i4i.2xlarge` (8 vCPU, 64 GiB RAM) |
| **Local Disk** | 200 GiB Ephemeral NVMe | 1.8 TB Hardware NVMe SSD (`/work`) |
| **Routing Mechanism** | EventBridge size rule: `numeric <= 53687091200` | EventBridge size rule: `numeric > 53687091200` |
| **Download Protocol** | 16 MiB chunk streaming | Parallel ranged reads (16 concurrent threads) |
| **Execution Cost** | Minimal per-second serverless cost | $\sim$\$0.69/hr spot/on-demand ($\sim$\$3.50 for a 5-hour 500 GiB run) |
| **Private Data Path** | AWS S3 Gateway Endpoint ($0 cross-AZ data fees) | AWS S3 Gateway Endpoint ($0 cross-AZ data fees) |
| **Evidence Storage Tier** | S3 Glacier Instant Retrieval (`GLACIER_IR`) | S3 Glacier Instant Retrieval (`GLACIER_IR`) |
| **Storage Cost** | $\sim$\$0.004 / GB-month (83% reduction vs Standard) | $\sim$\$0.004 / GB-month (83% reduction vs Standard) |

---

## Repository Structure

```text
dfirbaboon/
├── README.md                            # Architecture overview, compliance details, usage guide
├── Makefile                             # Build, test, push ECR container, and Terraform targets
├── .github/
│   └── workflows/
│       └── ci.yml                       # CI/CD pipeline: Python typing/tests, Terraform validate, Docker audit
├── tests/
│   ├── test_config.py                   # Unit tests for WorkerConfig validation and BYO resolution
│   ├── test_parsers.py                  # Unit tests for ForensicParser plugin architecture & safe_parse
│   └── test_hashes.py                   # Unit tests for dual SHA-256/MD5 hashing and acquisition checks
├── terraform/
│   ├── versions.tf                      # Terraform >= 1.6.0, AWS Provider >= 5.38.0
│   ├── variables.tf                     # Configurable prefix, thresholds, VPC/subnets, BYO inputs
│   ├── main.tf                          # Modular root composition orchestrating all infrastructure
│   ├── outputs.tf                       # Intake bucket name, ECR repo URL, ECS cluster ARN, Batch queue ARN
│   ├── environments/
│   │   └── enterprise-byo.tfvars.example# Turnkey configuration for regulated / pre-vended environments
│   └── modules/
│       ├── kms/                         # Customer Managed Key (CMK) with 90-day rotation & 30-day deletion
│       ├── s3/                          # S3 Intake (7-day lifecycle) & Audit Trail with TLS 1.2+ enforce
│       ├── network/                     # VPC subnet resolution, S3 Gateway endpoint ($0 data fee), SG
│       ├── iam/                         # Least-privilege Task Execution, Task, and Batch Roles
│       ├── compute/                     # ECR repo, ECS Fargate cluster, Batch EC2 NVMe compute environment
│       ├── events/                      # EventBridge dual size-routing rules (<= 50 GiB vs > 50 GiB)
│       └── monitoring/                  # CloudWatch KMS logs, CloudTrail S3 Data Events, and Metric Alarms
└── worker/
    ├── Dockerfile                       # Hardened Ubuntu 24.04 (non-root UID 10001, purged setuid/setgid)
    ├── requirements.txt                 # boto3, pytsk3, yara-python, tabulate
    ├── config.py                        # Strongly-typed immutable WorkerConfig dataclass with env overrides
    ├── entrypoint.py                    # Main orchestrator: CoC, SIGTERM traps, TSK, carving, S3 upload
    └── parsers/
        ├── __init__.py                  # Package exports and automatic parser registration
        ├── base.py                      # BaseParser ABC, ParserContext, ParserResult, and ParserFactory
        ├── tsk_parser.py                # Multi-volume mmls, fsstat, fls, icat, and mactime (TSKForensicParser)
        ├── carving.py                   # blkls unallocated extraction, PhotoRec carving, EXIF & keywords
        ├── yara_scanner.py              # YARA scanning over extracted/carved files and unallocated streams
        └── md_exporter.py               # Formats outputs into token-safe AI Markdown with YAML frontmatter
```

---

## Enterprise & Regulated Environments (BYO Architecture)

In controlled cloud environments, platform security teams or landing zone account vending machines frequently enforce strict **Service Control Policies (SCPs)** restricting the creation of IAM roles, KMS CMKs, and S3 buckets.

`dfirbaboon` is fully decoupled and supports a **"Bring Your Own" (BYO)** operational model:

### 1. Pre-Provisioned Resources Supported
* **KMS CMK**: Pass `create_kms_key = false` and `existing_kms_key_arn = "arn:aws:kms:..."`.
* **S3 Intake & Audit Buckets**: Pass `create_intake_bucket = false`, `existing_intake_bucket_name = "..."`, and `create_audit_trail_bucket = false`.
* **Central Forensic Evidence Lake**: Pass `create_vault_bucket = false`, `vault_bucket_name = "corp-evidence-lake"`, and an optional `vault_prefix = "cases/{incident_id}/"`. The worker skips administrative bucket creation (`s3:CreateBucket`, `s3:PutBucket*`) and writes evidence and analysis directly to the designated prefix within your central data lake.
* **IAM Governance & Permissions Boundaries**: Set `permissions_boundary_arn = "arn:aws:iam::...:policy/Boundary"` to satisfy landing zone boundary requirements, or set `create_iam_roles = false` to supply existing pre-vended role ARNs.
* **Enterprise VPC**: Pass `vpc_id` and private `subnet_ids`, and toggle `create_s3_vpc_endpoint = false` if the VPC already has an S3 Gateway Endpoint.

### 2. Deploying with Enterprise BYO
See [`terraform/environments/enterprise-byo.tfvars.example`](terraform/environments/enterprise-byo.tfvars.example) for a turnkey template:

```bash
cd terraform
terraform init
terraform plan -var-file="environments/enterprise-byo.tfvars"
terraform apply -var-file="environments/enterprise-byo.tfvars"
```

---

## Prerequisites

- **AWS CLI v2** configured with credentials targeting your deployment account (`aws sts get-caller-identity`).
- **Terraform** `>= 1.6.0`
- **Docker** `>= 24.0` (with `buildx` support for `linux/amd64` container builds)
- **GNU Make** & **Python** `>= 3.10`

---

## Quickstart & 1-Click Deployment

### 1. Initialize Terraform
```bash
make init
```

### 2. Provision Infrastructure (KMS, S3 Intake, ECS, Batch on EC2, EventBridge)
```bash
make deploy
```
> **Note:** By default, `terraform/` automatically discovers your account's default VPC and subnets. To deploy into specific private subnets, pass `-var="vpc_id=vpc-xxxx" -var='subnet_ids=["subnet-aaa","subnet-bbb"]'`.

### 3. Build & Push the Forensic Worker Container to Amazon ECR
```bash
make push
```

### 4. Trigger an End-to-End Test Evidence Drop
```bash
make test-drop
```
This target generates a synthetic forensic payload and uploads it to:
`s3://dfirbaboon-intake-<aws_account_id>/INC10001/test_disk.raw`

---

## Usage Guide: Ingesting Forensic Evidence

Upload any disk image or forensic artifact to the Intake S3 Bucket under an incident prefix matching `INC\d+` (case-insensitive):

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Example 1: Ingest Evidence with Collector Acquisition Hash Metadata (NIST SP 800-86)
aws s3 cp ./workstation_c_drive.E01 \
  s3://dfirbaboon-intake-${ACCOUNT_ID}/INC10492/workstation_c_drive.E01 \
  --metadata acquisition-sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Example 2: Ingest Evidence with Adjacent manifest.json
aws s3 cp ./server.raw s3://dfirbaboon-intake-${ACCOUNT_ID}/INC10492/server.raw
aws s3 cp ./manifest.json s3://dfirbaboon-intake-${ACCOUNT_ID}/INC10492/manifest.json

# Example 3: Standalone Windows Event Log or Triage Artifact
aws s3 cp ./Security.evtx s3://dfirbaboon-intake-${ACCOUNT_ID}/INC10492/Security.evtx
```

### Automated Pipeline Flow
1. **EventBridge Detection:** S3 emits an `Object Created` event to EventBridge, which inspects object size. Evidence $\le$ 50 GiB dispatches an `ecs:RunTask` on Fargate; evidence $>$ 50 GiB dispatches a `batch:SubmitJob` on EC2.
2. **Vault Preparation & Hardening:** The worker resolves the target bucket (per-incident vault or central enterprise evidence lake), verifies access, and configures S3 Object Lock and SSE-KMS.
3. **Evidence Download, Hashing & Acquisition Verification:** The evidence is downloaded to fast scratch disk, marked read-only (`chmod 0400`), hashed (`SHA-256`, `MD5`), and verified against the collector acquisition hash.
4. **Immediate Evidence Archiving & Checkpoint:** Raw evidence is copied directly into the vault as `GLACIER_IR` with an active S3 Legal Hold, and an initial `chain_of_custody.json` is vaulted before processing begins.
5. **Parallel Analysis Execution:**
   - **TSK Engine:** `mmls` detects partition layouts across all volumes; `fsstat` extracts file system metadata; `fls -d` identifies recoverable deleted files; `mactime` constructs supertimelines and extracts high-risk execution/persistence artifacts.
   - **Carving Engine:** Runs concurrently using `blkls` to extract unallocated blocks, carved via PhotoRec, with EXIF and keyword/credential searches.
   - **YARA Scanner:** Compiles rules and scans allocated files, carved files, and unallocated streams with MITRE ATT&CK technique tagging.
   - **Checkpoint Uploads:** Timelines and carved inventories are uploaded to S3 immediately as each phase finishes.
6. **Report Generation & Final Vaulting:** Markdown reports with FRE 1006 disclaimers and updated `chain_of_custody.json` manifests are uploaded to S3.

---

## YARA Rule Signatures & Anomaly Detection

`dfirbaboon` performs automated threat detection across all extracted files, carved objects, and unallocated disk streams using **YARA** and an automated Shannon entropy / file header anomaly inspector.

### 1. Built-in DFIR Ruleset
The worker compiles built-in signatures covering high-frequency adversary techniques:

| Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :---: | :---: | :--- |
| `Suspicious_PowerShell_Encoded_And_Cradle` | **HIGH** | T1059.001 | Detects `-EncodedCommand`, `FromBase64String`, `Net.WebClient` download cradles, and AMSI bypass strings (`AmsiUtils`, `amsiInitFailed`). |
| `Credential_Access_Mimikatz_And_LSASS` | **CRITICAL** | T1003 | Detects Mimikatz modules (`sekurlsa::logonpasswords`, `lsadump::sam`, `gentilkiwi`), LSASS process minidumps (`comsvcs.dll` + `MiniDumpWriteDump`), and NTDS database extractions (`ntds.dit`). |
| `Ransomware_ShadowCopy_Inhibit_System_Recovery` | **CRITICAL** | T1490 | Detects Volume Shadow Copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`), boot recovery inhibition (`bcdedit /set {default} recoveryenabled no`), and backup catalog tampering. |
| `Webshell_Execution_Indicators` | **HIGH** | T1505.003 | Detects PHP/ASPX/JSP execution primitives (`eval(base64_decode`, `passthru($_`, `shell_exec($_`, `WScript.Shell`, `/bin/sh -c`). |
| `Persistence_ScheduledTask_And_RunKey` | **MEDIUM** | T1053.005, T1547.001 | Detects Windows Registry Run/RunOnce keys, scheduled task creations (`schtasks /create`, `Register-ScheduledTask`), and service registrations (`sc.exe create`). |
| `Suspicious_Packed_UPX_Binary` | **MEDIUM** | T1027.002 | Detects UPX-packed binaries (`UPX0`, `UPX1`, `UPX!`) frequently used by adversaries to pack malicious payloads. |

### 2. File Header Magic & Entropy Anomaly Engine
In addition to string-based YARA rules, `dfirbaboon` inspects file magic signatures and Shannon entropy:
* **Extension Masquerading**: Flags critical anomalies where Windows PE (`MZ`) or Linux ELF (`\x7fELF`) binaries disguise themselves under non-executable extensions (`.txt`, `.log`, `.jpg`, `.pdf`, `.docx`, etc.).
* **Entropy Scoring**: Calculates Shannon entropy ($0.0 - 8.0$) across file streams to highlight packed, obfuscated, or encrypted payloads ($> 7.2$).

### 3. Adding Custom YARA Rules
You can easily extend the engine with your organization's custom rules or open-source threat intelligence feeds (e.g. Neo23x0 Signature-Base, ReversingLabs, Yara-Rules):

#### Method A: Drop Rules into `worker/rules/` (Container Build)
1. Add your `.yar` or `.yara` files to [`worker/rules/`](worker/rules/):
   ```bash
   cp my_threat_intel.yar worker/rules/
   ```
2. Rebuild and push the container image:
   ```bash
   make push
   ```
3. During startup, `YaraScanner` scans `/app/rules/` and compiles all custom rules into isolated namespaces named after the file stem.

#### Method B: Set `YARA_RULES_DIR` Environment Variable
Set the `YARA_RULES_DIR` environment variable to any local or mounted directory containing `.yar`/`.yara` files:
```bash
export YARA_RULES_DIR="/path/to/custom/yara_rules"
```

#### Evidentiary Integrity & Court Provenance (ISO 17025)
Whenever custom rules are loaded, `dfirbaboon` calculates the SHA-256 digest of every rule file and logs it into `chain_of_custody.json` under `sbom.yara_ruleset_sha256`. This ensures forensic reproducibility and prevents rule tampering claims during evidentiary challenges.

---

## AI-Friendly Markdown & Obsidian / LLM RAG Integration

Every Markdown file generated in `s3://<vault-bucket>/analysis/<filename>/markdown/` is strictly bounded to prevent LLM context window overflow and begins with standardized YAML frontmatter:

```yaml
---
pipeline: dfirbaboon
incident_id: INC10492
evidence_file: "workstation_c_drive.E01"
sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
md5: "d41d8cd98f00b204e9800998ecf8427e"
size_bytes: 10737418240
intake_utc: "2026-11-09T22:15:04Z"
processed_utc: "2026-11-09T22:18:49Z"
tags: [dfirbaboon, forensics, dfir, chain-of-custody, tsk, inc10492]
---
```

### Generated Reports
| Report Filename | Purpose |
| :--- | :--- |
| `00_CHAIN_OF_CUSTODY.md` | Cryptographic hashes (`SHA-256`, `MD5`), acquisition hash audit status, S3 Version IDs, ETag, intake/processing UTC timestamps, KMS Key ARN, and execution SBOM. |
| `01_TSK_FILE_SYSTEM_SUMMARY.md` | Multi-volume partition layout (`mmls`), filesystem metadata (`fsstat`), and recoverable deleted files (`fls -d`). |
| `02_HIGH_RISK_TIMELINE_ARTIFACTS.md` | High-signal timeline modifications from `mactime` (.exe, .dll, .ps1, persistence, scheduled tasks). |
| `03_YARA_AND_ANOMALIES.md` | YARA rule matches mapped to MITRE ATT&CK techniques, header mismatches, and entropy anomalies. |
| `04_CARVED_FILES_AND_UNALLOCATED.md` | Unallocated space (`blkls`) carved with PhotoRec, carved file inventory, EXIF metadata, and keyword hits (emails, URLs, credentials, IPs). |

### Syncing with Obsidian or LLM/RAG Pipelines
Download an incident's Markdown folder directly into an Obsidian vault or LangChain / LlamaIndex / Bedrock Knowledge Base directory:

```bash
aws s3 sync \
  s3://dfirbaboon-inc10492-${ACCOUNT_ID}/analysis/workstation_c_drive.E01/markdown/ \
  ./obsidian-dfir-vault/INC10492/
```
Because reports use `[[WikiLinks]]`, YAML frontmatter properties, and GitHub-flavored Markdown tables, Obsidian's **Dataview** and **Graph View** automatically link all evidence artifacts under their shared `incident_id` and `tags`.

---

## Cost Analysis

> Estimates use **us-east-1 on-demand list prices** (late 2025) and the Terraform defaults. Always confirm against the [AWS Pricing Calculator](https://calculator.aws/) for your region and usage. Figures are approximate.

The pipeline is fully serverless / scale-to-zero: **you pay for compute only while an image is being processed**. Batch runs with `min_vcpus = 0`, and Fargate tasks exist only for the duration of a job.

### 1. Idle (Always-On) Baseline
| Component | Driver | Est. Monthly Cost |
| :--- | :--- | ---: |
| KMS CMK | \$1.00 / key / month | \$1.00 |
| ECR (worker image, ~1 GB, up to 5 retained) | \$0.10 / GB-month | \$0.10 – \$0.50 |
| EventBridge rules, ECS cluster, Batch queue / compute env, IAM, S3 Gateway Endpoint | No charge when idle | \$0.00 |
| CloudTrail (1 management trail) | First copy of management events is free | \$0.00 |
| **Total idle** | | **~\$1.10 – \$1.50 / month** |

### 2. Per-Run Compute Cost
| Tier | Config (Terraform defaults) | Hourly Rate | Notes |
| :--- | :--- | ---: | :--- |
| **ECS Fargate** (≤ 50 GiB) | 4 vCPU, 8 GiB RAM, 100 GiB ephemeral | **~\$0.21 / hr** | \$0.04048/vCPU-hr + \$0.004445/GB-hr + \$0.000111/GB-hr for ephemeral storage above 20 GiB |
| **AWS Batch on EC2** (> 50 GiB) | `i4i.2xlarge` (8 vCPU, 64 GiB, 1.8 TB NVMe) | **~\$0.69 / hr** | On-demand; Batch scales back to 0 when the queue is empty |
| Batch root EBS (`batch_scratch_gib` = 1024 gp3) | \$0.08 / GB-month, prorated | **~\$0.11 / hr** | Fallback scratch; lower `batch_scratch_gib` to reduce this |
| Public IPv4 (when `assign_public_ip = true`) | \$0.005 / hr | ~\$0.005 / hr | Avoid by using private subnets + VPC endpoints / NAT |

**Typical job costs** (processing throughput varies with image content, fragmentation, and carving depth):

| Evidence Size | Tier | Est. Runtime | Est. Compute Cost |
| :--- | :--- | :--- | ---: |
| 1 – 10 GiB | Fargate | 0.25 – 1 hr | \$0.05 – \$0.21 |
| 50 GiB | Fargate | 1 – 3 hr | \$0.21 – \$0.62 |
| 200 GiB | Batch (i4i.2xlarge) | 3 – 5 hr | \$2.40 – \$4.00 |
| 500 GiB | Batch (i4i.2xlarge) | 5 – 10 hr | \$4.00 – \$8.00 |
| 1 TB | Batch (i4i.2xlarge) | 10 – 20 hr | \$8.00 – \$16.00 |

> Batch cost includes the instance plus root EBS volume (~\$0.80 / hr combined).

### 3. Storage Cost (Dominant Long-Term Cost)
| Storage | Rate | 200 GiB Example |
| :--- | :--- | ---: |
| Intake bucket (S3 Standard, 7-day lifecycle expiry) | \$0.023 / GB-month | ~\$1.07 one-time per image (7 days) |
| Vault raw evidence (`GLACIER_IR`) | \$0.004 / GB-month | **~\$0.80 / month** (\$9.60 / year) |
| Vault analysis outputs (timelines, carved inventory, reports; S3 Standard) | \$0.023 / GB-month | Typically < \$0.10 / month |
| `GLACIER_IR` retrieval | \$0.03 / GB | \$6.00 to read back 200 GiB |

> [!WARNING]
> Vault buckets use S3 Object Lock in **`COMPLIANCE` mode (365 days)** plus a Legal Hold. Evidence **cannot be deleted** by anyone (including root) until retention expires and the hold is released, so storage cost is a **committed** expense. Test with small files and consider shorter retention in dev/test accounts. `GLACIER_IR` also has a 90-day minimum storage duration and a 128 KB minimum billable object size.

### 4. Security, Audit & Observability
| Component | Driver | Est. Cost |
| :--- | :--- | ---: |
| CloudTrail S3 data events | \$0.10 per 100,000 events | < \$0.10 per image (multipart copy + hashing generate thousands of events) |
| CloudTrail log storage (audit bucket) | S3 Standard | ~\$0.01 – \$1 / month |
| KMS API requests | \$0.03 per 10,000 requests (S3 Bucket Keys enabled to minimize) | < \$0.10 per image |
| CloudWatch Logs | \$0.50 / GB ingested + \$0.03 / GB-month stored (90-day retention) | < \$0.10 per image |
| ECS Container Insights | Per-metric / per-log charges while tasks run | ~\$0.05 – \$0.50 / job |
| S3 Gateway Endpoint | Free; avoids NAT / data transfer fees for S3 traffic | \$0.00 |
| Same-region S3 → compute data transfer | Free within a region | \$0.00 |

### 5. Example Monthly Scenarios
| Scenario | Compute | Intake Storage | Vault Storage | Audit / Logs / KMS | **Approx. Total** |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Idle / Dev** (no cases) | \$0 | \$0 | \$0 | \$1.10 | **~\$1.50** |
| **Light** (5 cases/mo × 20 GiB, Fargate) | ~\$1 | ~\$0.50 | ~\$0.40 (new) | ~\$1.50 | **~\$4** |
| **Moderate** (10 cases/mo × 100 GiB, mixed) | ~\$15 | ~\$5 | ~\$4 (new) | ~\$3 | **~\$27** (+\$4 / mo added each month as evidence accumulates) |
| **Heavy IR retainer** (4 × 500 GiB large images/mo) | ~\$25 | ~\$11 | ~\$8 (new) | ~\$5 | **~\$49** (+\$8 / mo added each month) |

### 6. Cost Optimization Tips
* **Keep images ≤ `large_image_threshold_gib` on Fargate** where possible; it avoids the i4i instance and 1 TB EBS fallback volume.
* **Lower `batch_scratch_gib`** (default 1024) if your largest images fit on the 1.8 TB local NVMe.
* **Reduce `intake_retention_days`** (default 7) to shorten the Standard-tier intake window.
* **Use private subnets** and set `assign_public_ip = false` to avoid IPv4 charges (requires VPC endpoints for ECR / CloudWatch).
* **Disable `enable_carving`** (`ENABLE_CARVING=false`) for quick triage; PhotoRec carving is the longest-running phase.
* **Use shorter `retention_days`** in non-production accounts to avoid long-lived COMPLIANCE-mode storage commitments.
* **Set `create_cloudtrail = false`** if your organization already runs an organization-wide trail with S3 data events (BYO mode).
* **Set an AWS Budget alert** (e.g., \$25/month) on the `Project = dfirbaboon` cost-allocation tag applied by Terraform to all resources.

---

## Security & Secrets Hygiene

* **No credentials are stored in this repository.** The worker and Terraform use the AWS default credential chain (IAM roles on ECS/Batch; SSO / environment variables locally).
* Never paste `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN` values into files, commits, issues, or chat tools. If a key is ever exposed, **rotate/revoke it immediately**.
* `.gitignore` excludes Terraform state (`*.tfstate*`), `*.tfvars`, `.env*`, private keys, `local_output/` (case data), and evidence images. Only `*.tfvars.example` templates are committed; use placeholder values (e.g. account ID `123456789012`).
* Terraform state contains account IDs and resource ARNs; use a remote encrypted backend (S3 + DynamoDB lock) for shared deployments.
* Consider adding [`gitleaks`](https://github.com/gitleaks/gitleaks) or GitHub secret scanning / push protection to CI.

---

## Testing & Quality Assurance

The codebase includes comprehensive unit tests covering the configuration manager, parser factory architecture, dual cryptographic hashing, and acquisition hash verification:

```bash
# Run unit tests locally
make test

# Validate Terraform modules and composition
make validate

# Run unit tests inside the hardened container
docker run --rm dfirbaboon:latest python3 -m unittest discover -s tests -v
```
