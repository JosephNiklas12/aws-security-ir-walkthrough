S3 backdoor walkthrough · MD
# Scenario 04 — S3 Bucket Policy Backdoor
 
## Overview
 
| Field | Detail |
|---|---|
| Technique | Backdoor S3 Bucket Policy |
| Stratus ID | `aws.exfiltration.s3-backdoor-bucket-policy` |
| MITRE ATT&CK | T1530 — Data from Cloud Storage |
| Tactic | Exfiltration |
| Severity | High |
| Date Executed | 2026-05-29 |
 
---
 
## Scenario Context
 
An attacker with valid IAM credentials modifies an S3 bucket policy to grant public or external access to sensitive data. The bucket appears normal in the AWS console — no alarms, no errors — but any unauthenticated user on the internet can now read its contents. This technique is commonly used as a quiet, persistent exfiltration channel that survives key rotation and IAM changes.
 
Real-world examples include the Capital One breach (2019) where misconfigured S3 access exposed 100 million customer records, and numerous fintech incidents where attackers silently backdoored KYC document buckets.
 
---
 
## MITRE ATT&CK Mapping
 
```
Initial Access      T1078.004   Valid Accounts: Cloud Accounts
Exfiltration        T1530       Data from Cloud Storage
Defense Evasion     T1078       Valid Accounts (blends with legitimate activity)
Collection          T1213       Data from Information Repositories
```
 
---
 
## Lab Execution
 
### Step 1 — Warmup
 
```powershell
.\stratus.exe warmup aws.exfiltration.s3-backdoor-bucket-policy
```
 
Stratus provisions a target S3 bucket with sensitive data via Terraform.
 
### Step 2 — Detonate
 
```powershell
.\stratus.exe detonate aws.exfiltration.s3-backdoor-bucket-policy
```
 
Stratus modifies the bucket policy to grant public read access. The bucket is now open to the internet.
 
---
 
## Detection
 
### GuardDuty Finding
 
```
Policy:S3/BucketAnonymousAccessGranted
  Bucket: stratus-red-team-bdbp-rclbymmgij
  Region: us-east-1
  Time: 2026-05-29T20:00:56Z
```
 
### CloudTrail Analysis — Step 1: Find the policy change
 
Query for `PutBucketPolicy` — the API call that fires when an S3 bucket policy is modified:
 
```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy --region us-east-1
```
 
**Real CloudTrail finding captured:**
 
```json
{
    "EventName": "PutBucketPolicy",
    "EventTime": "2026-05-29T20:00:56Z",
    "Username": "iamadminSCS-C03",
    "Resources": [
        {
            "ResourceType": "AWS::S3::Bucket",
            "ResourceName": "arn:aws:s3:::stratus-red-team-bdbp-rclbymmgij"
        }
    ]
}
```
 
**Reading the finding:**
 
| Field | Value | Meaning |
|---|---|---|
| EventName | PutBucketPolicy | Bucket policy was modified |
| Username | iamadminSCS-C03 | Identity that made the change |
| EventTime | 2026-05-29T20:00:56Z | When it happened |
| ResourceName | stratus-red-team-bdbp-rclbymmgij | Which bucket was backdoored |
 
> **Note:** `UserId` (e.g. `AIDA[REDACTED]`) is an internal AWS identifier — always look for the `Username` field for the human-readable IAM identity.
 
### CloudTrail Analysis — Step 2: Check for data exfiltration
 
Query for `GetObject` — the API call that fires when someone reads an object from S3:
 
```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject --region us-east-1
```
 
---
 
## ⚠️ Critical Finding: S3 Data Events Are Not Logged by Default
 
```
Results: { "Events": [] }
```
 
Empty results do NOT mean no data was accessed. They mean CloudTrail was not configured to log S3 data events.
 
```
CloudTrail event types:
  Management events  → API calls that manage AWS resources
                        (PutBucketPolicy, CreateUser, StopLogging)
                        Logged by default ✅
 
  Data events        → API calls that access data inside resources
                        (GetObject, PutObject, DeleteObject)
                        NOT logged by default ⚠️
```
 
In this scenario the bucket was publicly accessible for an unknown period. Without data event logging there is no way to determine:
- Whether data was accessed
- How many objects were read
- What IP addresses accessed the data
- Whether exfiltration occurred
**This is a critical visibility gap in any production environment.**
 
### How to Enable S3 Data Event Logging
 
**Via AWS Console (recommended):**
 
```
CloudTrail → Trails → [your trail]
→ Data events → Edit
→ Data event type: S3
→ Log selector template: Log all events
→ Save changes
```
 
**Via Terraform (preventive — deploy before an incident):**
 
```hcl
resource "aws_cloudtrail_event_data_store" "s3_data_events" {
  name = "s3-data-events"
 
  advanced_event_selector {
    name = "Log all S3 data events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
  }
}
```
 
---
 
## Prevention
 
The most effective control against this attack is enabling S3 Block Public Access at the account level. This prevents any bucket policy from granting public access regardless of what an attacker does.
 
**Terraform:**
 
```hcl
resource "aws_s3_bucket_public_access_block" "public_access_block" {
  bucket = aws_s3_bucket.my_secure_bucket.id
 
  block_public_acls       = true   # blocks public ACL grants
  block_public_policy     = true   # blocks public bucket policies
  ignore_public_acls      = true   # ignores existing public ACLs
  restrict_public_buckets = true   # restricts all public bucket access
}
```
 
With all four set to `true`, an attacker **cannot** backdoor a bucket policy to grant public access — AWS blocks it at the infrastructure level before the policy takes effect.
 
**Apply at account level for maximum protection:**
 
```powershell
aws s3control put-public-access-block \
  --account-id [ACCOUNT-ID] \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```
 
---
 
## Response
 
### Step 1 — Remove the backdoor bucket policy
 
```powershell
aws s3api delete-bucket-policy --bucket stratus-red-team-bdbp-rclbymmgij
```
 
No output = success. The bucket policy is removed and public access is blocked.
 
### Step 2 — Verify bucket is no longer public
 
```powershell
aws s3api get-bucket-policy-status --bucket stratus-red-team-bdbp-rclbymmgij
```
 
Expected output:
```json
{
    "PolicyStatus": {
        "IsPublic": false
    }
}
```
 
### Step 3 — Enable S3 Block Public Access on the bucket
 
```powershell
aws s3api put-public-access-block \
  --bucket stratus-red-team-bdbp-rclbymmgij \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```
 
### Step 4 — Disable the compromised IAM key
 
```powershell
aws iam list-access-keys --user-name iamadminSCS-C03
aws iam update-access-key --user-name iamadminSCS-C03 --access-key-id AKIA[KEY-ID] --status Inactive
```
 
> ⚠️ Verify this is NOT your active IR key before disabling. Run `aws sts get-caller-identity` first and compare the AccessKeyId.
 
### Step 5 — Assess exfiltration scope
 
Without S3 data event logging enabled, you cannot determine with certainty whether data was accessed. Document this as an unknown in your incident report and escalate accordingly.
 
If data event logging was enabled, query for access during the exposure window:
 
```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject --region us-east-1
```
 
Look for any `GetObject` events with timestamps after the `PutBucketPolicy` event at `20:00:56Z`.
 
---
 
## Roadblocks Encountered & How We Solved Them
 
### Roadblock 1 — S3 data events not logged by default
 
**What happened:**
After detecting the bucket policy change, ran `GetObject` lookup in CloudTrail to check for exfiltration. Returned empty results — initially interpreted as no data access.
 
**How we solved it:**
Recognized that CloudTrail does not log S3 data events by default. Empty results were inconclusive, not confirmation of no access. Enabled S3 data event logging via the CloudTrail console for future scenarios.
 
**Lesson:**
```
Always verify data event logging is enabled before relying on
GetObject results. Empty ≠ clean.
 
Management events → logged by default
Data events       → must be explicitly enabled
 
Add S3 data event logging to your standard lab and
production CloudTrail configuration.
```
 
---
 
### Roadblock 2 — JSON encoding errors with here-string
 
**What happened:**
Attempted to enable S3 data event logging via CLI using a here-string JSON file. PowerShell wrote the file with UTF-8 BOM encoding, causing AWS CLI to reject it with:
 
```
Error parsing parameter: Expected: '=', received: 'ï' for input: ï»¿{
```
 
**How we solved it:**
Used the AWS Console instead for this configuration step. Console is always a valid fallback when CLI encoding issues arise.
 
**Lesson:**
```
For complex JSON policy documents in PowerShell:
  Option 1 → Console (always works, no encoding issues)
  Option 2 → -Encoding ascii instead of utf8
  Option 3 → Inline with escaped quotes for short policies
 
When CLI is fighting you, the Console is not cheating.
```
 
---
 
## Key Lessons
 
**1. S3 data events are not logged by default**
`PutBucketPolicy` is a management event and always logged. `GetObject` is a data event and requires explicit configuration. A bucket can be publicly exposed and actively exfiltrating data with zero CloudTrail evidence if data events aren't enabled. Enable them on all production buckets.
 
**2. Empty CloudTrail results ≠ no activity**
Always verify your logging configuration before drawing conclusions from empty results. Absence of evidence is not evidence of absence in cloud forensics.
 
**3. S3 Block Public Access is your strongest preventive control**
Four settings, all set to true, applied at the account level. Prevents public bucket policies from taking effect regardless of IAM permissions. Deploy via Terraform as standard infrastructure baseline — not as a reactive control.
 
**4. Detection without data events = incomplete picture**
GuardDuty caught the policy change. CloudTrail confirmed who did it. But without data event logging the exfiltration scope was unknown. Layered detection requires both management AND data event logging.
 
**5. UserId vs Username**
```
UserId:   AIDASS2WC7DXI6XPBRAQV  → internal AWS identifier
Username: iamadminSCS-C03         → IAM user name for investigation
```
Always use Username for subsequent CloudTrail lookups and investigation workflows.
 
---
 
## S3 Security API Reference
 
```powershell
# Find bucket policy changes
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy --region us-east-1
 
# Find data access (requires data event logging enabled)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject --region us-east-1
 
# Check if bucket is public
aws s3api get-bucket-policy-status --bucket [BUCKET-NAME]
 
# Remove backdoor bucket policy
aws s3api delete-bucket-policy --bucket [BUCKET-NAME]
 
# Enable block public access on bucket
aws s3api put-public-access-block --bucket [BUCKET-NAME] --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
 
# Enable block public access at account level
aws s3control put-public-access-block --account-id [ACCOUNT-ID] --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
 
# List all buckets
aws s3 ls
 
# Check bucket policy
aws s3api get-bucket-policy --bucket [BUCKET-NAME]
```
 
---
 
## Cleanup
 
```powershell
.\stratus.exe cleanup aws.exfiltration.s3-backdoor-bucket-policy
```
 
---
 
## Further Reading
 
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [CloudTrail S3 Event Reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [MITRE ATT&CK T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [Stratus Red Team — aws.exfiltration.s3-backdoor-bucket-policy](https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/)
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
