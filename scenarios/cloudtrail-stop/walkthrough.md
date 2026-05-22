# Scenario 02 — CloudTrail Logging Disabled

## Overview

| Field | Detail |
|---|---|
| Technique | Stop CloudTrail Trail |
| Stratus ID | `aws.defense-evasion.cloudtrail-stop` |
| MITRE ATT&CK | T1562.008 — Disable Cloud Logs |
| Tactic | Defense Evasion |
| Severity | High |
| Date Executed | 2026-05-22 |

---

## Scenario Context

An attacker with valid IAM credentials stops CloudTrail logging before moving laterally through the environment. With logging disabled, subsequent API calls — privilege escalation, data access, persistence mechanisms — leave no audit trail. This technique is commonly used as a setup step before the primary attack objective.

This technique was observed in real-world breaches where attackers disabled logging immediately after gaining initial access to eliminate forensic evidence of their activity.

---

## MITRE ATT&CK Mapping

```
Initial Access      T1078.004   Valid Accounts: Cloud Accounts
Defense Evasion     T1562.008   Disable Cloud Logs
Impact              T1485       Data Destruction (logs destroyed)
```

---

## Lab Execution

### Step 1 — Warmup

```powershell
.\stratus.exe warmup aws.defense-evasion.cloudtrail-stop
```

Stratus provisions a dedicated CloudTrail trail as the attack target.

### Step 2 — Detonate

```powershell
.\stratus.exe detonate aws.defense-evasion.cloudtrail-stop
```

Output:
```
Stopping CloudTrail trail stratus-red-team-ct-stop-trail-znoyanuelu
```

CloudTrail logging is now stopped on the target trail. API calls made after this point are not recorded.

---

## Detection

### Why Detection is Still Possible

CloudTrail captures the `StopLogging` API call **before** logging stops. GuardDuty operates independently of CloudTrail using its own data sources and fires immediately on the finding.

```
Attacker calls StopLogging
  → CloudTrail records the StopLogging event (last event before going dark)
  → GuardDuty detects the action independently
  → Finding fires: Stealth:IAMUser/CloudTrailLoggingDisabled
```

If GuardDuty is not enabled, this action may go undetected entirely.

### GuardDuty Finding

```
Stealth:IAMUser/CloudTrailLoggingDisabled
  Principal: arn:aws:iam::[REDACTED]:user/iamadminSCS-C03
  Region: us-east-1
  Time: 2026-05-22T08:15:48Z
```

### CloudTrail Analysis

Query for the `StopLogging` event:

```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --region us-east-1
```

**Real CloudTrail finding captured:**

```json
{
    "EventId": "973abea3-3599-4533-a505-26d2ab4d981e",
    "EventName": "StopLogging",
    "ReadOnly": "false",
    "AccessKeyId": "AKIA[REDACTED]",
    "EventTime": "2026-05-22T08:15:48",
    "EventSource": "cloudtrail.amazonaws.com",
    "Username": "iamadminSCS-C03",
    "Resources": [
        {
            "ResourceType": "AWS::CloudTrail::Trail",
            "ResourceName": "stratus-red-team-ct-stop-trail-znoyanuelu"
        }
    ]
}
```

### Reading the Finding

| Field | Value | Meaning |
|---|---|---|
| EventName | StopLogging | API call that was made |
| Username | iamadminSCS-C03 | Identity that made the call |
| EventTime | 2026-05-22T08:15:48 | When it happened |
| ResourceName | stratus-red-team-ct-stop-trail-znoyanuelu | Trail that was stopped |
| AccessKeyId | AKIA[REDACTED] | Key used to make the call |

### What to Look For in a Real Incident

- `StopLogging` or `DeleteTrail` events outside maintenance windows
- Source IP from unexpected geography
- Username that doesn't match expected automation or admin accounts
- `StopLogging` immediately followed by silence in CloudTrail — gap in log continuity
- GuardDuty finding `Stealth:IAMUser/CloudTrailLoggingDisabled`

---

## Response

### Step 1 — Restart CloudTrail logging immediately

```powershell
aws cloudtrail start-logging --name stratus-red-team-ct-stop-trail-znoyanuelu
```

No output = success in AWS CLI.

### Step 2 — Verify logging is restored

```powershell
aws cloudtrail get-trail-status --name stratus-red-team-ct-stop-trail-znoyanuelu
```

Look for:
```json
"IsLogging": true
```

### Step 3 — Identify the logging gap

Determine exactly how long CloudTrail was stopped:

```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StartLogging --region us-east-1
```

Cross-reference the `StopLogging` and `StartLogging` timestamps. Everything in between is a blind spot — you have no CloudTrail evidence of attacker activity during that window.

### Step 4 — Check other detection sources for the gap period

CloudTrail was blind but other sources were not:

```powershell
# Check VPC Flow Logs for unusual traffic during the gap
# Check GuardDuty for any findings during the gap window
aws guardduty list-findings --detector-id [YOUR_DETECTOR_ID] --region us-east-1
```

### Step 5 — Investigate the identity that stopped logging

```powershell
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=iamadminSCS-C03 --region us-east-1
```

Review all API calls made by that identity before and after the `StopLogging` event.

---

## Key Lessons

**1. GuardDuty is your safety net**
If CloudTrail is your only detection source, an attacker can disable it and go completely dark. GuardDuty operates independently and catches the disabling action itself. Never rely on a single detection layer.

**2. The StopLogging event is the last breadcrumb**
CloudTrail captures its own shutdown. That final event tells you who did it, when, and from where — giving you a starting point for investigation even after logging stops.

**3. Defense evasion precedes the real attack**
Attackers stop logging as a setup step, not an end goal. The absence of logs after `StopLogging` is itself evidence. Assume lateral movement occurred during the blind window and investigate accordingly.

**4. Log continuity monitoring**
Production environments should alert on gaps in CloudTrail log delivery, not just on explicit `StopLogging` events. An attacker who deletes the trail entirely won't generate a `StopLogging` event — but the log gap will still appear.

**5. Multiple log sources = Defense in Depth**
```
CloudTrail stopped     → API call history gone
GuardDuty still runs   → threat detection active
VPC Flow Logs still run → network traffic visible
S3 access logs still run → data access partially visible
```
Layer your logging so no single action can blind you completely.

---

## Cleanup

```powershell
.\stratus.exe cleanup aws.defense-evasion.cloudtrail-stop
```

---

## References

- [Stratus Red Team — aws.defense-evasion.cloudtrail-stop](https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-stop/)
- [MITRE ATT&CK T1562.008](https://attack.mitre.org/techniques/T1562/008/)
- [AWS CloudTrail — Start Logging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartLogging.html)
- [GuardDuty Finding — CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
