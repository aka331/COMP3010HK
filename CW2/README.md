# COMP3010HK (CW2) — BOTSv3 Incident Analysis (Splunk)

> **Module:** COMP3010HK Security Operations & Incident Management  
> **Coursework:** CW2 (BOTSv3 Incident Analysis + Presentation)  
> **Dataset:** Boss of the SOC v3 (BOTSv3)  
> **Tooling:** Splunk Enterprise on Ubuntu VM  
> **Video (≤10 mins):** [YouTube link here]  

---

## 1) Introduction

This investigation analyzes AWS-related security events in the **Frothly** environment using the **BOTSv3** dataset. The goal is to demonstrate SOC-style incident investigation using Splunk SPL by answering a selected set of 200-level guided questions, supported with evidence (queries + screenshots) and professional reflection.

**Scope**
- AWS activity analysis primarily via CloudTrail logs.
- S3 misconfiguration (public bucket access) investigation.
- Endpoint outlier identification via host monitoring logs.

**Assumptions**
- BOTSv3 is pre-indexed under `index=botsv3`.
- Time range is set to “All time” unless stated.

---

## 2) SOC Roles & Incident Handling Reflection

A SOC investigation typically involves:
- **Tier 1:** triage, alert validation, basic enrichment.
- **Tier 2:** deeper SPL investigations, correlation across data sources, incident scoping.
- **Tier 3 / IR Lead:** containment strategy, root cause analysis, lessons learned, detection engineering improvements.

**Incident handling phases applied**
- **Preparation:** logging, ingestion validation, baseline dashboards.
- **Detection & Analysis:** identify IAM users, MFA gaps, S3 ACL changes, suspicious uploads, endpoint outliers.
- **Containment:** isolate exposed S3 bucket and revoke public ACLs.
- **Eradication & Recovery:** remediate misconfiguration, enforce least privilege and MFA, re-check access logs.
- **Post-incident:** create detections (MFA bypass, S3 ACL changes), improve monitoring and response runbooks.

---

## 3) Installation & Data Preparation

### 3.1 Splunk Installation (Ubuntu VM)

Download and extract Splunk into `/opt`, then start with license acceptance:

```bash
wget -O splunk-10.0.1.tgz "https://download.splunk.com/products/splunk/releases/10.0.1/linux/splunk-10.0.1-c486717c322b-linux-amd64.tgz"
sudo tar -xzf splunk-10.0.1.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
```

### 3.2 BOTSv3 Dataset Ingestion

Download and extract the BOTSv3 dataset app into the Splunk apps directory:

```bash
cd ~/Downloads
wget -O botsv3_data_set.tgz "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz"
sudo tar zxvf botsv3_data_set.tgz -C /opt/splunk/etc/apps/
sudo /opt/splunk/bin/splunk restart
```
### 3.3 Access + Validation

Splunk Web access:

- Inside VM: http://127.0.0.1:8000

- From host: http://<VM_IP>:8000 (NAT/bridged dependent)

Validation SPL:

```spl
index=botsv3 earliest=0
```

## 4) Investigation — Guided Questions (AWS + Endpoint)

### 4.1 Key Findings (Summary)
| Question | Answer                                                    |
| -------- | --------------------------------------------------------- |
| Q1       | `bstoll,btun,splunk_access,web_admin`                     |
| Q2       | `userIdentity.sessionContext.attributes.mfaAuthenticated` |
| Q3       | `E5-2676`                                                 |
| Q4       | `ab45689d-69cd-41e7-8705-5350402cf7ac`                    |
| Q5       | `bstoll`                                                  |
| Q6       | `frothlywebcode`                                          |
| Q7       | `OPEN_BUCKET_PLEASE_FIX.txt`                              |
| Q8       | `BSTOLL-L.froth.ly`                                       |


### 4.2 Evidence + SPL (per question)

**Q1) IAM users who accessed AWS services**

Objective: Enumerate IAM usernames observed in CloudTrail (successful/unsuccessful).

```sql
index=botsv3 earliest=0 sourcetype=aws:cloudtrail
| stats count by userIdentity.userName
```

Result: ```bstoll, btun, splunk_access, web_admin```

Evidence: screenshot of SPL + stats table.

**Q2) Field to alert on AWS API activity without MFA (exclude console logins)**

Objective: Determine the best JSON path for MFA state relevant to API session usage.

```sql
index=botsv3 earliest=0 sourcetype=aws:cloudtrail
| regex "MFA"
```

Chosen field: ```userIdentity.sessionContext.attributes.mfaAuthenticated```
Rationale: reflects whether the session credentials were MFA-authenticated for API calls (more reliable than console-login-only fields).
