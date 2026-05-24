# Scenario 01 — IAM Backdoor User

## Overview

| Field | Detail |
|---|---|
| Technique | Create Access Key on Existing IAM User |
| Stratus ID | `aws.persistence.iam-backdoor-user` |
| MITRE ATT&CK | T1136.003 — Create Cloud Account |
| Tactic | Persistence |
| Severity | High |
| Date Executed | 2026-05-20 |

---

## Scenario Context

An attacker has compromised an IAM service account credential — likely leaked via a public GitHub commit or CI/CD pipeline log. Using that initial access, they create a backdoor access key on a legitimate IAM user to establish persistent access that survives key rotation of the original compromised credential.

This technique was observed in real-world breaches including the Lapsus$ campaigns and multiple crypto exchange incidents.

---

## MITRE ATT&CK Mapping

```
Initial Access      T1078.004   Valid Accounts: Cloud Accounts
Persistence         T1136.003   Create Cloud Account
Defense Evasion     T1078       Valid Accounts (blends with legitimate activity)
```

---

## Lab Execution

### Step 1 — Warmup

Stratus provisions a target IAM user via Terraform:

```powershell
.\stratus.exe warmup aws.persistence.iam-backdoor-user
```

Output:
```
2026/05/20 20:58:06 Warming up aws.persistence.iam-backdoor-user
2026/05/20 20:58:06 Initializing Terraform
2026/05/20 20:58:20 Applying Terraform to spin up technique prerequisites
2026/05/20 20:58:26 IAM user stratus-red-team-backdoor-u-user ready
```

A real IAM user now exists in the lab account as the attack target.

### Step 2 — Detonate

```powershell
.\stratus.exe detonate aws.persistence.iam-backdoor-user
```

Output:
```
2026/05/20 21:00:57 Creating access key on legit IAM user to simulate backdoor
2026/05/20 21:00:57 Successfully created access key AKIASS2WC7DXODCGG3FT
```

Stratus created a real access key on the target IAM user. This key is now active and usable by an attacker.

---

## Detection

### CloudTrail Analysis

Query for `CreateAccessKey` events on the target user:

```powershell
aws cloudtrail lookup-events `
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=stratus-red-team-backdoor-u-user `
  --region us-east-1 `
  --output json
```

**Real CloudTrail finding captured:**

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "stratus-red-team-backdoor-u-user",
            "AccessKeyId": "AKIA[REDACTED]",
            "Status": "Inactive",
            "CreateDate": "2026-05-21T03:00:57+00:00"
        }
    ]
}
```

### What to Look For

In a real incident, the following indicators signal malicious access key creation:

- `CreateAccessKey` event outside normal deployment windows
- Source IP from unexpected geography or Tor exit node
- Key created on a service account by a human user principal
- No corresponding change ticket or deployment pipeline trigger
- Key created shortly after unusual reconnaissance events (`ListUsers`, `ListRoles`)

### GuardDuty

GuardDuty may surface the following finding type within 15 minutes of detonation:

```
Persistence:IAMUser/AnomalousBehavior
  — Unusual API call CreateAccessKey detected
  — Principal: [compromised user]
  — Region: us-east-1
```

---

## Response

### Containment

**Step 1 — Identify all access keys on the compromised user:**

```powershell
aws iam list-access-keys `
  --user-name stratus-red-team-backdoor-u-user
```

**Step 2 — Disable the backdoor key immediately:**

```powershell
aws iam update-access-key `
  --user-name stratus-red-team-backdoor-u-user `
  --access-key-id AKIA[REDACTED] `
  --status Inactive
```

**Step 3 — Verify it is inactive:**

```powershell
aws iam list-access-keys `
  --user-name stratus-red-team-backdoor-u-user
```

Expected output:
```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "stratus-red-team-backdoor-u-user",
            "AccessKeyId": "AKIA[REDACTED]",
            "Status": "Inactive",
            "CreateDate": "2026-05-21T03:00:57+00:00"
        }
    ]
}
```

**Step 4 — Check CloudTrail for any API calls made using the backdoor key before containment:**

```powershell
aws cloudtrail lookup-events `
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA[REDACTED] `
  --region us-east-1
```

This tells you what the attacker did with the key before you disabled it.

---

## Key Lessons

**1. Evidence before action**
Always pull CloudTrail before disabling keys. Revoking immediately destroys your ability to understand what the attacker already did and whether they pivoted.

**2. Keys vs. sessions**
Disabling an access key stops future API calls but does NOT terminate active `sts:AssumeRole` sessions. If the attacker assumed a role using the key, that session survives key revocation for up to 1 hour. Use the `aws:TokenIssueTime` IAM condition to revoke active sessions.

**3. Backdoor keys survive primary key rotation**
Organizations often respond to a leaked key by rotating the original. If an attacker creates a backdoor key first, that key is completely unaffected by the rotation. Always audit all keys on all users, not just the known-compromised one.

**4. Check for downstream persistence**
A backdoor key is often step two, not the end goal. Always check what the key was used for — lateral movement to roles, Lambda modification, S3 access — before declaring containment complete.

---

## Cleanup

```powershell
.\stratus.exe cleanup aws.persistence.iam-backdoor-user
```

This removes all Terraform-provisioned infrastructure from the lab account.

---

## References

- [Stratus Red Team — aws.persistence.iam-backdoor-user](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-user/)
- [MITRE ATT&CK T1136.003](https://attack.mitre.org/techniques/T1136/003/)
- [AWS CloudTrail — Lookup Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)
- [Revoking IAM Role Temporary Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
