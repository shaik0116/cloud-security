# 🔐 AWS Cloud Security Audit Toolkit

> Automated AWS security scanner built in Python that detects
> IAM and S3 misconfigurations before attackers exploit them.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![AWS](https://img.shields.io/badge/AWS-boto3-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Ireland](https://img.shields.io/badge/Built%20in-Ireland-009A44)

---

## 🎯 What This Does

This tool automatically scans an AWS account and flags
security misconfigurations that cause real world data breaches.

It runs 6 security checks across IAM and S3 — the two most
commonly misconfigured services in AWS accounts.

---

## 🔍 Security Checks

### IAM — Identity and Access Management
| Check | What It Detects | Severity |
|-------|----------------|----------|
| MFA Status | Users without multi-factor authentication | 🔴 Critical |
| Access Key Age | Active keys older than 90 days | 🟡 High |
| Root MFA | Root account without MFA protection | 🔴 Critical |

### S3 — Simple Storage Service
| Check | What It Detects | Severity |
|-------|----------------|----------|
| Public Access Block | Buckets accessible by anyone online | 🔴 Critical |
| Encryption | Buckets without AES256 encryption | 🟡 High |
| Access Logging | Buckets without audit trail logging | 🟠 Medium |

---

## 📋 Real Output From My AWS Account
```
=======================================================
   AWS SECURITY AUDIT — IAM + S3
   Run at: 2026-02-24 11:17:30
=======================================================

🔍 CHECK 1: MFA Status for All Users

  ✅ SAFE  | Security-Admin  | MFA OK | Created: 2026-02-23

🔍 CHECK 2: Access Key Age

  ✅ SAFE  | Security-Admin  | Key age: 0 days

🔍 CHECK 3: Root Account MFA

  ✅ SAFE  | Root account has MFA enabled

=======================================================
   IAM SUMMARY
=======================================================
  Total users scanned : 1
  Users WITH MFA      : 1 ✅
  Users WITHOUT MFA   : 0 ❌
  ✅ All IAM checks passed!

=======================================================
   S3 BUCKET SECURITY CHECKS
=======================================================

  📦 Scanning bucket: security-test-bajis-2026
     ❌ Public Access  | NOT blocked — RISK!
     ✅ Encryption     | Enabled (AES256)
     ⚠️  Access Logging | Not enabled

  🚨 CRITICAL — Fix immediately:
     → security-test-bajis-2026 is publicly accessible!

=======================================================
   FULL AUDIT COMPLETE
=======================================================
```

---

## 🏗️ How It Works
```
Your Laptop
     │
     │  Python boto3 API calls
     ▼
AWS Account (eu-west-1 Dublin)
├── IAM Service
│   ├── Scan all users for MFA
│   ├── Check access key ages
│   └── Verify root MFA status
└── S3 Service
    ├── List all buckets
    ├── Check public access block
    ├── Verify encryption enabled
    └── Check access logging
```

---

## 🚀 Run This Yourself

**Requirements:** Python 3.8+, AWS account, boto3

**Step 1 — Clone:**
```bash
git clone https://github.com/shaik0116/cloud-security.git
cd cloud-security
```

**Step 2 — Install dependencies:**
```bash
pip install boto3
```

**Step 3 — Configure AWS credentials:**
```bash
aws configure
```

**Step 4 — Run the audit:**
```bash
python day1_iam_audit.py
```

---

## 🌍 Real World Impact

| This Tool Catches | Real Breach It Prevents |
|-------------------|------------------------|
| No MFA on users | Most common AWS account takeover vector |
| Public S3 buckets | Capital One breach — 100M records, $80M fine |
| Old access keys | Leaked credentials sold on dark web markets |
| No root MFA | Complete account takeover if root is compromised |

---

## 🔑 What I Used To Build This

- **Python 3.11** — core scripting language
- **boto3** — official AWS SDK for Python
- **AWS IAM** — Identity and Access Management service
- **AWS S3** — Simple Storage Service
- **AWS CLI** — command line tool for AWS
- **VS Code** — development environment

---

## 📍 About

Building cloud security skills hands-on from Ireland.
Every project is deployed on real AWS infrastructure.

📍 Ireland 🇮🇪 | 💼 Targeting Cloud Security Engineer roles
```

**Command 4 — Save:**
```
Ctrl + S
```

**Command 5 — Push to GitHub:**
```
git add README.md
git commit -m "Update README with accurate project details"
git push
```

---

Then go to:
```
https://github.com/shaik0116/cloud-security
