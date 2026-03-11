Cloud Security Posture Dashboard

A real-time AWS security monitoring dashboard built with Python Flask and Chart.js.
Displays live security findings, severity breakdown, and overall security score — exactly like enterprise SOC tools.


📸 What It Looks Like
┌─────────────────────────────────────────────────────────┐
│  ☁ AWS Security Posture Dashboard      Last updated: now │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   20%  Overall Security Score                           │
│   [████░░░░░░░░░░░░░░░░░░░░░░]                          │
│                                                          │
├──────────┬──────────┬──────────┬────────────────────────┤
│    2     │    3     │    3     │    2                   │
│ CRITICAL │  HIGH    │  MEDIUM  │  PASSED                │
├──────────┴──────────┴──────────┴────────────────────────┤
│                                                          │
│  SECURITY FINDINGS          │  SEVERITY CHART           │
│  🔴 CRITICAL S3 public...   │                           │
│  🔴 CRITICAL Root MFA...    │      [Doughnut Chart]     │
│  🟡 HIGH Access key age     │                           │
│  🟡 HIGH S3 encryption      │                           │
│  🟡 HIGH CloudTrail logs    │                           │
│  🔵 MEDIUM S3 logging       │                           │
└─────────────────────────────────────────────────────────┘

🎯 What This Project Does
This dashboard gives a complete view of your AWS security posture in real time:

Security Score — Overall percentage based on passed vs failed controls
Severity Cards — Count of Critical, High, Medium findings and Passed controls
Findings List — Every security finding with service name and region
Doughnut Chart — Visual breakdown of findings by severity
Live Refresh — Dashboard auto-updates every 30 seconds


🔍 Security Findings It Monitors
FindingSeverityServiceS3 bucket public access not blocked🔴 CRITICALS3Root account MFA not enabled🔴 CRITICALIAMAccess key older than 90 days🟡 HIGHIAMS3 bucket encryption not enabled🟡 HIGHS3CloudTrail not enabled in all regions🟡 HIGHCloudTrailS3 access logging not enabled🔵 MEDIUMS3IAM password policy not configured🔵 MEDIUMIAMVPC flow logs not enabled🔵 MEDIUMVPCMFA enabled on Security-Admin✅ PASSEDIAMS3 versioning enabled✅ PASSEDS3

🏗 Architecture
Browser (localhost:5000)
        │
        │  HTTP Request
        ▼
  Flask Web Server (app.py)
        │
        ├── GET /              → Serves dashboard.html
        │
        └── GET /api/findings  → Returns JSON with:
                                  - All security findings
                                  - Severity counts
                                  - Security score
                                  - Last updated timestamp

🛠 Tech Stack
TechnologyPurposePython 3Core programming languageFlaskLightweight web framework — serves the dashboardboto3AWS SDK — connects to real AWS infrastructureChart.jsJavaScript library for doughnut chartHTML/CSSProfessional dark theme dashboard UIREST API/api/findings endpoint for live data

📁 Project Structure
project4-security-dashboard/
│
├── app.py                  ← Flask web server and API
│   ├── generate_findings() ← Security findings data
│   ├── GET /               ← Serves the dashboard
│   └── GET /api/findings   ← Returns JSON findings
│
├── templates/
│   └── dashboard.html      ← Complete dashboard UI
│       ├── Score bar
│       ├── Severity cards
│       ├── Findings list
│       └── Doughnut chart
│
├── static/                 ← Static assets folder
│
└── README.md               ← This file

⚡ How To Run It
Step 1 — Clone The Repository
bashgit clone https://github.com/shaik0116/cloud-security
cd project4-security-dashboard
Step 2 — Install Dependencies
bashpip install flask boto3
Step 3 — Configure AWS Credentials (Optional)
If you want to connect to real AWS Security Hub findings:
bashaws configure
AWS Access Key ID:     your-access-key
AWS Secret Access Key: your-secret-key
Default region name:   eu-west-1
Default output format: json
Step 4 — Run The Dashboard
bashpython app.py
Step 5 — Open In Browser
http://localhost:5000

🔌 API Reference
GET /api/findings
Returns all security findings and summary statistics.
Response:
json{
  "findings": [
    {
      "id": "F001",
      "title": "S3 bucket public access not blocked",
      "severity": "CRITICAL",
      "service": "S3",
      "region": "eu-north-1",
      "status": "FAILED"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 3,
    "passed": 2,
    "score": 20,
    "last_updated": "2026-03-11 14:32:00"
  }
}

🔒 Security Note
This tool is read-only. It never modifies, creates, or deletes any AWS resources.
For production use:

Create a dedicated read-only IAM user
Attach the SecurityAudit AWS managed policy
Delete the audit user after use
👤 Author
Shaik Baji
Cloud Security Engineer — Ireland
GitHub: shaik0116

📄 What This Project Demonstrates
✅ Python Flask web development
✅ REST API design and implementation
✅ AWS security knowledge — IAM, S3, CloudTrail, VPC
✅ Data visualisation with Chart.js
✅ Professional dashboard UI design
✅ Real-time data refresh architecture
✅ Cloud security posture concepts
✅ CIS AWS Benchmark awareness

Built on real AWS infrastructure · Open source · Free to use