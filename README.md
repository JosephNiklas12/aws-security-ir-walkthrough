# AWS Incident Response Lab

A hands-on cloud security lab for practicing real-world AWS attack detection and incident response using [Stratus Red Team](https://github.com/DataDog/stratus-red-team) by Datadog.

This repo documents real TTPs detonated against a sandboxed AWS account, paired with defender responses, CloudTrail analysis, and containment procedures. Each scenario maps to MITRE ATT&CK and mirrors techniques observed in real-world cloud breaches.

---

## Purpose

Most cloud security training is theoretical. This lab is not.

Every scenario in this repo was executed against a live AWS environment. The CloudTrail output is real. The containment commands were tested. The goal is to build muscle memory for incident response before it matters.

---

## Lab Environment

| Component | Detail |
|---|---|
| Cloud Provider | AWS (dedicated sandbox account) |
| Primary Region | us-east-1 |
| Attack Tool | Stratus Red Team v2.32.1 |
| Detection | AWS CloudTrail, GuardDuty, Security Hub |
| OS | Windows 11 + PowerShell |

> **Warning:** All techniques were detonated against an isolated lab account with no production workloads. Never run these against a real environment.

---

## Prerequisites

Before running any scenario:

1. **Dedicated AWS account** — never use a personal or work account
2. **IAM user with AdministratorAccess** — for lab purposes only
3. **CloudTrail enabled** — multi-region, log file validation on
4. **GuardDuty enabled** — free 30-day trial available
5. **AWS CLI configured** — `aws configure`
6. **Stratus Red Team installed** — see [setup guide](tools/stratus-setup.md)

Sanity check before every session:
```powershell
aws sts get-caller-identity
```
Confirm the Account ID matches your lab account before proceeding.

---

## Scenarios

| # | Technique | MITRE ATT&CK | Status |
|---|---|---|---|
| 01 | [IAM Backdoor User](scenarios/iam-backdoor/walkthrough.md) | T1136.003 — Create Cloud Account | ✅ Complete |
| 02 | [CloudTrail Disable](scenarios/cloudtrail-stop/walkthrough.md) | T1562.008 — Disable Cloud Logs | ✅ Complete |
| 03 | [Lambda Code Overwrite](scenarios/lambda-overwrite/walkthrough.md) | T1565.001 — Stored Data Manipulation | ✅ Complete |
| 04 | [S3 Bucket Policy Backdoor](scenarios/s3-backdoor/walkthrough.md) | T1530 — Data from Cloud Storage | ✅ Complete |
| 05 | Secrets Manager Enumeration | T1552.001 — Credentials in Files | 🔜 Planned |

---

## Lab Workflow

Each scenario follows the same structure:

```
1. Warmup    → Stratus provisions prerequisites via Terraform
2. Detonate  → Attack TTP executes against live environment
3. Detect    → CloudTrail / GuardDuty analysis
4. Respond   → Containment commands executed
5. Cleanup   → Stratus tears down all lab resources
```

---

## Tools

- [Stratus Red Team](https://stratus-red-team.cloud) adversary emulation for cloud
- [AWS CLI](https://aws.amazon.com/cli/) detection and response commands
- [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) audit logging
- [AWS GuardDuty](https://aws.amazon.com/guardduty/) threat detection

---

## Security Notes

This repo follows strict credential hygiene:

- No AWS access keys committed
- Account IDs redacted in all output samples
- No real customer or production data used
- All lab resources cleaned up after each session

---

## Author

Joseph Crawford
Cloud Security | AWS Security Specialist 
