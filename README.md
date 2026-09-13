# Linux Authentication & IAM Security Analytics

> Cybersecurity | IAM | Authentication Security | SQL | MySQL | Power BI | Security Analytics

## 🔐 Project Overview

This project analyzes 500,000 Linux authentication events from a cybersecurity and Identity & Access Management (IAM) perspective.

The project uses MySQL and SQL to analyze authentication activity, identify failed login behavior, investigate security anomalies, analyze account-level risk, and examine network-related activity.

The analysis is presented through an interactive Power BI security analytics dashboard.

The overall workflow is:

Linux Authentication Dataset  
↓  
MySQL Database  
↓  
SQL Security Analysis  
↓  
Risk & Anomaly Analysis  
↓  
Power BI Dashboard  
↓  
IAM / Cybersecurity Insights

---

## 🎯 Project Objectives

- Analyze Linux authentication activity.
- Identify failed and successful authentication events.
- Analyze security anomaly categories.
- Identify accounts with repeated failed authentication activity.
- Analyze source IPs associated with failed authentication.
- Investigate privilege-escalation-labelled events.
- Analyze brute-force-labelled activity.
- Analyze geo-anomaly-labelled activity.
- Analyze port-scan-labelled activity.
- Develop a custom account-level risk score.
- Build an interactive Power BI security dashboard.
- Apply IAM and cybersecurity concepts to authentication-log analysis.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| MySQL 8.0 | Store and analyze authentication logs |
| SQL | Security analysis and risk calculations |
| Power BI | Interactive security dashboard |
| Linux Authentication Concepts | IAM and authentication-security analysis |
| GitHub | Project documentation and portfolio |

---

## 📊 Dataset

The final dataset contains **500,000 Linux authentication events**.

### Dataset Statistics

| Metric | Count |
|---|---:|
| Total Events | 500,000 |
| Failed Events | 254,099 |
| Successful Events | 245,901 |
| Normal Events | 475,293 |
| Brute Force Events | 6,233 |
| Privilege Escalation Events | 6,221 |
| Geo Anomaly Events | 6,128 |
| Port Scan Events | 6,125 |
| Non-Normal / Anomalous Events | 24,707 |

### Dataset Fields

- `timestamp`
- `source_ip`
- `server`
- `username`
- `service`
- `attempts`
- `status`
- `port`
- `protocol`
- `comment`
- `anomaly_label`

---

# 🔎 Security Analysis

The project performs security analysis across four major areas.

## 🔑 Authentication Security

The analysis includes:

- Total authentication events
- Failed vs successful authentication
- Top users by failed-login activity
- Top source IPs associated with failed authentication
- Authentication status distribution

## 🚨 Anomaly Analysis

The dataset contains the following anomaly categories:

- Brute Force
- Privilege Escalation
- Geo Anomaly
- Port Scan

These events are analyzed using:

- Username
- Source IP
- Server
- Protocol
- Port
- Authentication status
- Timestamp

## 🌐 Network Analysis

Network-related analysis includes:

- Authentication activity by protocol
- Server authentication activity
- Destination-port analysis
- Port-scan-labelled activity
- Network context around suspicious events

## 👤 Account Risk Analysis

User accounts are prioritized using a custom project-defined risk score.

---

# ⚠️ Account Risk Scoring

The project uses the following risk-scoring formula:

```text
Risk Score =
Failed Logins
+ (Brute Force Events × 5)
+ (Privilege Escalation Events × 5)
+ (Geo Anomaly Events × 3)
+ (Port Scan Events × 3)

Project Limitations:
Anomaly labels are provided by the dataset and are not independently verified attacks.
The Risk Score is a custom project-defined heuristic.
The project uses authentication-log data rather than a live enterprise IAM platform.
Business roles and asset criticality are not included.
High risk does not automatically mean that an account is compromised.
Authentication anomalies require additional investigation and contextual validation.

Future Improvements:
Integrate real IAM or identity-provider data.
Add user roles and privilege information.
Add account-risk severity categories.
Add time-windowed authentication detection.
Add source-IP reputation analysis.
Add user and IP drill-through investigations.
Add automated Power BI refresh.
Add security alerting for high-risk authentication activity.
Integrate additional security-log sources.
Extend the project toward real-world IAM monitoring workflows.
