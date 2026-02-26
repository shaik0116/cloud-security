import boto3
from datetime import datetime, timezone

# Connect to AWS services
iam = boto3.client('iam', region_name='eu-north-1')
s3  = boto3.client('s3',  region_name='eu-north-1')

# ─────────────────────────────────────────────
# COLLECT ALL SECURITY DATA
# ─────────────────────────────────────────────

print("Running AWS Security Audit...")

# IAM Data
all_users   = iam.list_users()['Users']
mfa_pass    = []
mfa_fail    = []
old_keys    = []
key_results = []

for user in all_users:
    username = user['UserName']
    created  = user['CreateDate'].strftime('%Y-%m-%d')

    # Check MFA
    mfa_devices = iam.list_mfa_devices(
        UserName=username
    )['MFADevices']

    if len(mfa_devices) == 0:
        mfa_fail.append(username)
        mfa_status = 'FAIL'
    else:
        mfa_pass.append(username)
        mfa_status = 'PASS'

    # Check access key age
    keys = iam.list_access_keys(
        UserName=username
    )['AccessKeyMetadata']

    for key in keys:
        key_status  = key['Status']
        key_created = key['CreateDate']
        age_days    = (datetime.now(timezone.utc) - key_created).days

        if age_days > 90 and key_status == 'Active':
            old_keys.append(username)
            key_age_status = 'FAIL'
        else:
            key_age_status = 'PASS'

        key_results.append({
            'username':   username,
            'age_days':   age_days,
            'key_status': key_status,
            'result':     key_age_status
        })

# Check root MFA
account_summary = iam.get_account_summary()['SummaryMap']
root_mfa        = account_summary.get('AccountMFAEnabled', 0)
root_mfa_status = 'PASS' if root_mfa else 'FAIL'

# S3 Data
all_buckets         = s3.list_buckets()['Buckets']
public_buckets      = []
unencrypted_buckets = []
unlogged_buckets    = []
bucket_results      = []

for bucket in all_buckets:
    bucket_name = bucket['Name']
    created     = bucket['CreationDate'].strftime('%Y-%m-%d')

    # Check public access
    try:
        public_access = s3.get_public_access_block(
            Bucket=bucket_name
        )
        config      = public_access['PublicAccessBlockConfiguration']
        all_blocked = all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ])
        public_status = 'PASS' if all_blocked else 'FAIL'
        if not all_blocked:
            public_buckets.append(bucket_name)
    except Exception:
        public_status = 'FAIL'
        public_buckets.append(bucket_name)

    # Check encryption
    try:
        encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        rules      = encryption['ServerSideEncryptionConfiguration']['Rules']
        enc_status = 'PASS' if rules else 'FAIL'
        enc_type   = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] if rules else 'None'
        if not rules:
            unencrypted_buckets.append(bucket_name)
    except Exception:
        enc_status = 'FAIL'
        enc_type   = 'None'
        unencrypted_buckets.append(bucket_name)

    # Check logging
    try:
        logging_config = s3.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in logging_config:
            log_status = 'PASS'
        else:
            log_status = 'WARN'
            unlogged_buckets.append(bucket_name)
    except Exception:
        log_status = 'WARN'
        unlogged_buckets.append(bucket_name)

    bucket_results.append({
        'name':          bucket_name,
        'created':       created,
        'public_status': public_status,
        'enc_status':    enc_status,
        'enc_type':      enc_type,
        'log_status':    log_status,
    })

# ─────────────────────────────────────────────
# CALCULATE SCORES
# ─────────────────────────────────────────────

total_checks  = 3 + (len(all_buckets) * 3)
failed_checks = len(mfa_fail) + len(old_keys) + (0 if root_mfa else 1) + len(public_buckets) + len(unencrypted_buckets)
passed_checks = total_checks - failed_checks
score_pct     = int((passed_checks / total_checks * 100)) if total_checks > 0 else 100

if score_pct >= 90:
    grade       = 'A'
    grade_color = '#2E7D32'
    grade_bg    = '#E8F5E9'
elif score_pct >= 70:
    grade       = 'B'
    grade_color = '#F57F17'
    grade_bg    = '#FFF8E1'
else:
    grade       = 'C'
    grade_color = '#C62828'
    grade_bg    = '#FFEBEE'

# ─────────────────────────────────────────────
# BUILD HTML REPORT
# ─────────────────────────────────────────────

scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def status_badge(status):
    if status == 'PASS':
        return '<span style="background:#2E7D32;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;">✅ PASS</span>'
    elif status == 'FAIL':
        return '<span style="background:#C62828;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;">❌ FAIL</span>'
    else:
        return '<span style="background:#F57F17;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;">⚠️ WARN</span>'

# Build IAM user rows
iam_rows = ''
for user in all_users:
    username    = user['UserName']
    created     = user['CreateDate'].strftime('%Y-%m-%d')
    mfa_s       = 'PASS' if username in mfa_pass else 'FAIL'
    key_result  = next((k for k in key_results if k['username'] == username), None)
    key_s       = key_result['result'] if key_result else 'N/A'
    age         = key_result['age_days'] if key_result else 'N/A'

    iam_rows += f"""
    <tr>
        <td>{username}</td>
        <td>{created}</td>
        <td>{status_badge(mfa_s)}</td>
        <td>{age} days</td>
        <td>{status_badge(key_s)}</td>
    </tr>
    """

# Build S3 bucket rows
s3_rows = ''
if not bucket_results:
    s3_rows = '<tr><td colspan="5" style="text-align:center;color:#666;">No S3 buckets found</td></tr>'
else:
    for b in bucket_results:
        s3_rows += f"""
        <tr>
            <td>{b['name']}</td>
            <td>{b['created']}</td>
            <td>{status_badge(b['public_status'])}</td>
            <td>{status_badge(b['enc_status'])} {b['enc_type']}</td>
            <td>{status_badge(b['log_status'])}</td>
        </tr>
        """

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Security Audit Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #F5F7FA; color: #1C1C1E; }}

  .header {{ background: linear-gradient(135deg, #0D2137 0%, #1A7F8E 100%); color: white; padding: 40px; }}
  .header h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 6px; }}
  .header p {{ font-size: 14px; opacity: 0.8; }}

  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}

  .score-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
  .score-card {{ background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .score-card .number {{ font-size: 36px; font-weight: 700; }}
  .score-card .label {{ font-size: 12px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}

  .grade-card {{ background: {grade_bg}; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .grade-card .number {{ font-size: 36px; font-weight: 700; color: {grade_color}; }}

  .section {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .section h2 {{ font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #0D2137; border-left: 4px solid #1A7F8E; padding-left: 12px; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #0D2137; color: white; padding: 10px 14px; text-align: left; font-weight: 600; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #F0F0F0; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #F9FAFB; }}

  .alert-box {{ border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; font-size: 14px; }}
  .alert-critical {{ background: #FFEBEE; border-left: 4px solid #C62828; color: #C62828; }}
  .alert-warn {{ background: #FFF8E1; border-left: 4px solid #F57F17; color: #F57F17; }}
  .alert-pass {{ background: #E8F5E9; border-left: 4px solid #2E7D32; color: #2E7D32; }}

  .footer {{ text-align: center; color: #999; font-size: 12px; padding: 20px; }}

  .root-status {{ display: inline-block; padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 14px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔐 AWS Security Audit Report</h1>
  <p>Account: 650251715192 &nbsp;|&nbsp; Region: eu-north-1 &nbsp;|&nbsp; Scanned: {scan_time}</p>
</div>

<div class="container">

  <!-- SCORE CARDS -->
  <div class="score-grid">
    <div class="grade-card">
      <div class="number">{grade}</div>
      <div class="label">Security Grade</div>
    </div>
    <div class="score-card">
      <div class="number" style="color:#1A7F8E;">{score_pct}%</div>
      <div class="label">Score</div>
    </div>
    <div class="score-card">
      <div class="number" style="color:#2E7D32;">{passed_checks}</div>
      <div class="label">Checks Passed</div>
    </div>
    <div class="score-card">
      <div class="number" style="color:#C62828;">{failed_checks}</div>
      <div class="label">Issues Found</div>
    </div>
  </div>

  <!-- ALERTS -->
  <div class="section">
    <h2>⚡ Findings Summary</h2>

    {''.join([f'<div class="alert-box alert-critical">🚨 CRITICAL: User <b>{u}</b> has no MFA — account takeover risk</div>' for u in mfa_fail])}
    {''.join([f'<div class="alert-box alert-critical">🚨 CRITICAL: User <b>{u}</b> has access keys older than 90 days</div>' for u in set(old_keys)])}
    {''.join([f'<div class="alert-box alert-critical">🚨 CRITICAL: Bucket <b>{b}</b> is publicly accessible</div>' for b in public_buckets])}
    {''.join([f'<div class="alert-box alert-critical">❌ HIGH: Bucket <b>{b}</b> has no encryption</div>' for b in unencrypted_buckets])}
    {''.join([f'<div class="alert-box alert-warn">⚠️ MEDIUM: Bucket <b>{b}</b> has no access logging</div>' for b in unlogged_buckets])}
    {'<div class="alert-box alert-critical">🚨 CRITICAL: Root account has NO MFA enabled</div>' if not root_mfa else ''}

    {'<div class="alert-box alert-pass">✅ All checks passed — account is secure</div>' if failed_checks == 0 else ''}
  </div>

  <!-- IAM SECTION -->
  <div class="section">
    <h2>👤 IAM — Identity and Access Management</h2>

    <p style="margin-bottom:12px;font-size:14px;">
      Root Account MFA:
      <span class="root-status" style="background:{'#E8F5E9' if root_mfa else '#FFEBEE'};color:{'#2E7D32' if root_mfa else '#C62828'};">
        {'✅ Enabled' if root_mfa else '❌ Not Enabled'}
      </span>
    </p>

    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Created</th>
          <th>MFA Status</th>
          <th>Key Age</th>
          <th>Key Status</th>
        </tr>
      </thead>
      <tbody>
        {iam_rows}
      </tbody>
    </table>
  </div>

  <!-- S3 SECTION -->
  <div class="section">
    <h2>🪣 S3 — Simple Storage Service</h2>
    <table>
      <thead>
        <tr>
          <th>Bucket Name</th>
          <th>Created</th>
          <th>Public Access</th>
          <th>Encryption</th>
          <th>Logging</th>
        </tr>
      </thead>
      <tbody>
        {s3_rows}
      </tbody>
    </table>
  </div>

  <!-- WHAT TO DO -->
  <div class="section">
    <h2>🔧 Recommended Actions</h2>
    <table>
      <thead>
        <tr>
          <th>Priority</th>
          <th>Action</th>
          <th>How To Fix</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span style="color:#C62828;font-weight:bold;">Critical</span></td>
          <td>Enable MFA on all IAM users</td>
          <td>IAM → Users → Security credentials → Assign MFA device</td>
        </tr>
        <tr>
          <td><span style="color:#C62828;font-weight:bold;">Critical</span></td>
          <td>Block public access on all S3 buckets</td>
          <td>S3 → Bucket → Permissions → Block public access → Edit → Enable all</td>
        </tr>
        <tr>
          <td><span style="color:#F57F17;font-weight:bold;">High</span></td>
          <td>Rotate access keys older than 90 days</td>
          <td>IAM → Users → Security credentials → Create new key → Delete old key</td>
        </tr>
        <tr>
          <td><span style="color:#F57F17;font-weight:bold;">Medium</span></td>
          <td>Enable S3 access logging</td>
          <td>S3 → Bucket → Properties → Server access logging → Enable</td>
        </tr>
      </tbody>
    </table>
  </div>

</div>

<div class="footer">
  Generated by AWS Security Audit Toolkit &nbsp;|&nbsp; {scan_time} &nbsp;|&nbsp; Built in Ireland 🇮🇪
</div>

</body>
</html>"""

# ─────────────────────────────────────────────
# SAVE THE REPORT
# ─────────────────────────────────────────────

report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

with open(report_filename, 'w', encoding='utf-8') as f:
    f.write(html)

print(f"\n✅ Report generated: {report_filename}")
print(f"   Open this file in your browser to view the report")
print(f"\n   Security Score: {score_pct}% — Grade: {grade}")
print(f"   Checks passed:  {passed_checks}")
print(f"   Issues found:   {failed_checks}")
