# Stratus Red Team — Windows Setup Guide

## Prerequisites

- Windows 10/11
- PowerShell
- AWS CLI installed ([download](https://aws.amazon.com/cli/))
- Dedicated AWS lab account with AdministratorAccess IAM user

---

## Installation

Stratus Red Team ships as a single binary. No installer required.

**Step 1 — Download the binary**

Go to the [latest release](https://github.com/DataDog/stratus-red-team/releases/latest) and download:
```
stratus-red-team_Windows_x86_64.tar.gz
```

> Note: Only `.tar.gz` is available for Windows — there is no `.zip` binary release. Avoid the `Source code` assets.

**Step 2 — Extract the binary**

PowerShell has a built-in `tar` command. Navigate to your Downloads folder and extract:

```powershell
cd $env:USERPROFILE\Downloads
tar -xzf stratus-red-team_Windows_x86_64.tar.gz
```

This drops `stratus.exe` directly in your Downloads folder.

**Step 3 — Verify**

```powershell
.\stratus.exe version
```

Expected output:
```
stratus version v2.32.1
```

---

## AWS Credentials Setup

**Step 1 — Create an IAM access key**

```
AWS Console → IAM → Users → your-lab-user
→ Security credentials → Create access key
→ Use case: CLI
→ Download .csv immediately — secret is only shown once
```

**Step 2 — Configure AWS CLI**

```powershell
aws configure
```

Enter when prompted:
```
AWS Access Key ID:     AK**...
AWS Secret Access Key: ...
Default region:        us-east-1
Default output format: json
```

**Step 3 — Verify credentials**

Always run this before any lab session:
```powershell
aws sts get-caller-identity
```

Confirm the Account ID matches your lab account before proceeding.

---

## Session Setup

Every new PowerShell session requires:

```powershell
# Navigate to Stratus binary
cd $env:USERPROFILE\Downloads

# Set AWS region (required by Stratus)
$env:AWS_REGION = "us-east-1"

# Verify AWS identity
aws sts get-caller-identity
```

---

## Basic Commands

```powershell
# List all available attack techniques
.\stratus.exe list

# Filter to AWS only
.\stratus.exe list --platform aws

# Show details on a specific technique
.\stratus.exe show aws.persistence.iam-backdoor-user

# Warmup (provision prerequisites only, don't attack yet)
.\stratus.exe warmup aws.persistence.iam-backdoor-user

# Detonate (execute the attack)
.\stratus.exe detonate aws.persistence.iam-backdoor-user

# Revert (undo the attack side effects)
.\stratus.exe revert aws.persistence.iam-backdoor-user

# Cleanup (tear down all lab infrastructure)
.\stratus.exe cleanup aws.persistence.iam-backdoor-user
```

---

## Recommended Lab Pattern

Open two PowerShell windows side by side:

```
Window 1 (Attacker)     Window 2 (Defender)
────────────────────    ────────────────────
.\stratus.exe warmup    aws cloudtrail lookup-events ...
.\stratus.exe detonate  aws iam list-access-keys ...
.\stratus.exe cleanup   aws guardduty list-findings ...
```

Warmup first, switch to defender window and start monitoring, then detonate. This mirrors real incident conditions where the defender doesn't know the attack is coming.

---

## Troubleshooting

**"you are not authenticated against AWS"**
```powershell
$env:AWS_REGION = "us-east-1"
aws sts get-caller-identity
```

**".\stratus.exe is not recognized"**
```powershell
# Make sure you're in the right directory
cd $env:USERPROFILE\Downloads
pwd
```

**OneDrive path confusion**
Windows Documents may sync to OneDrive, causing path mismatches. Use Downloads or explicitly use the full path:
```powershell
& "C:\Users\$env:USERNAME\Downloads\stratus.exe" version
```
