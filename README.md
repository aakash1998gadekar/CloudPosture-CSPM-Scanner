# ☁️ CloudPosture — Cloud Security Posture Management (CSPM) Scanner

<p align="center">
  <strong>Automated AWS Security Misconfiguration Detection & CIS Benchmark Compliance</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/CIS_Benchmark-v2.0-red" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
</p>

---

## 📖 What is CloudPosture?

**CloudPosture** is a portfolio-grade Cloud Security Posture Management (CSPM) tool that scans AWS environments for security misconfigurations, maps findings to CIS AWS Benchmark v2.0, and provides actionable remediation guidance through an interactive dashboard.

### The Problem It Solves:
Organizations migrate to AWS but leave S3 buckets public, security groups wide open, IAM policies overpermissive, and encryption disabled. Manual auditing across 200+ services is impossible — **misconfigurations cause 80% of cloud breaches**.

CloudPosture automates this entire process: scanning 50+ security checks across IAM, S3, EC2, RDS, and CloudTrail — presenting compliance scores, risk ratings, and fix instructions in one unified dashboard.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **50+ Security Checks** | Covers IAM, S3, EC2, RDS, CloudTrail, VPC |
| 📋 **CIS Benchmark Mapping** | Every finding maps to CIS AWS Benchmark v2.0 |
| ⚖️ **Risk Scoring** | Critical/High/Medium/Low with blast radius analysis |
| 📊 **Compliance Dashboard** | Visual pass/fail per category with trend |
| 🔧 **Remediation Guidance** | Actionable fix steps + Terraform/CLI snippets |
| 🎬 **Demo Mode** | Mocked AWS responses — no account needed |
| 🐳 **Docker Ready** | One command deployment |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/yourusername/CloudPosture.git
cd CloudPosture

# Install dependencies
pip install -r requirements.txt

# Run (Demo Mode - no AWS account needed)
uvicorn backend.app.main:app --reload

# Open dashboard
# http://localhost:8000
```

### With Docker:
```bash
docker-compose up --build
# Open http://localhost:8000
```

---

## 🏗️ Architecture

```
CloudPosture/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app
│   │   ├── config.py            # Configuration
│   │   ├── models/
│   │   │   ├── findings.py      # Finding data models
│   │   │   └── schemas.py       # Pydantic schemas
│   │   ├── routes/
│   │   │   ├── scanner.py       # Scan trigger endpoints
│   │   │   └── dashboard.py     # Dashboard data endpoints
│   │   ├── services/
│   │   │   ├── scanner_engine.py    # Core scan orchestrator
│   │   │   ├── checks/
│   │   │   │   ├── iam_checks.py    # IAM security checks
│   │   │   │   ├── s3_checks.py     # S3 security checks
│   │   │   │   ├── ec2_checks.py    # EC2/VPC security checks
│   │   │   │   ├── rds_checks.py    # RDS security checks
│   │   │   │   └── cloudtrail_checks.py  # Logging checks
│   │   │   ├── demo_data.py     # Mock AWS responses
│   │   │   └── cis_mapping.py   # CIS Benchmark mapping
│   │   └── utils/
│   │       └── severity.py      # Severity scoring
│   └── tests/
│       └── test_scanner.py
├── frontend/
│   ├── index.html
│   └── static/
│       ├── css/style.css
│       └── js/dashboard.js
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🔒 Security Checks

### IAM (12 checks)
- Root account MFA enabled
- No root access keys
- Password policy strength
- Unused credentials (90+ days)
- Users without MFA
- Overpermissive policies (*)
- Cross-account trust

### S3 (10 checks)
- Public bucket access
- Bucket encryption
- Versioning enabled
- Access logging
- Block public access settings
- Bucket policy analysis

### EC2/VPC (12 checks)
- Security group open ports (0.0.0.0/0)
- Default VPC usage
- EBS encryption
- Public IP on instances
- IMDSv2 enforcement
- VPC Flow Logs

### RDS (8 checks)
- Public accessibility
- Encryption at rest
- Multi-AZ deployment
- Backup retention
- Deletion protection

### CloudTrail (8 checks)
- Trail enabled in all regions
- Log file validation
- S3 bucket access logging
- CloudWatch integration
- KMS encryption

---

## 💡 Skills Demonstrated

- ✅ Cloud Security Posture Management (CSPM)
- ✅ CIS Benchmarks & compliance frameworks
- ✅ AWS security services (IAM, S3, EC2, RDS, CloudTrail)
- ✅ Risk prioritization at cloud scale
- ✅ Security automation
- ✅ Python async programming
- ✅ Full-stack development

---

## 📄 License

MIT License
