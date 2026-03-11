from flask import Flask, render_template, jsonify
from datetime import datetime
import random

app = Flask(__name__)

def generate_findings():
    findings = [
        {"id": "F001", "title": "S3 bucket public access not blocked", "severity": "CRITICAL", "service": "S3", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F002", "title": "Root account MFA not enabled", "severity": "CRITICAL", "service": "IAM", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F003", "title": "Access key older than 90 days", "severity": "HIGH", "service": "IAM", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F004", "title": "S3 bucket encryption not enabled", "severity": "HIGH", "service": "S3", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F005", "title": "CloudTrail not enabled in all regions", "severity": "HIGH", "service": "CloudTrail", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F006", "title": "S3 access logging not enabled", "severity": "MEDIUM", "service": "S3", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F007", "title": "IAM password policy not configured", "severity": "MEDIUM", "service": "IAM", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F008", "title": "VPC flow logs not enabled", "severity": "MEDIUM", "service": "VPC", "region": "eu-north-1", "status": "FAILED"},
        {"id": "F009", "title": "MFA enabled on Security-Admin", "severity": "LOW", "service": "IAM", "region": "eu-north-1", "status": "PASSED"},
        {"id": "F010", "title": "S3 versioning enabled", "severity": "LOW", "service": "S3", "region": "eu-north-1", "status": "PASSED"},
    ]
    return findings

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/findings')
def get_findings():
    findings = generate_findings()
    critical = len([f for f in findings if f['severity'] == 'CRITICAL' and f['status'] == 'FAILED'])
    high     = len([f for f in findings if f['severity'] == 'HIGH'     and f['status'] == 'FAILED'])
    medium   = len([f for f in findings if f['severity'] == 'MEDIUM'   and f['status'] == 'FAILED'])
    passed   = len([f for f in findings if f['status'] == 'PASSED'])
    total    = len(findings)
    score    = int((passed / total) * 100)
    return jsonify({
        'findings': findings,
        'summary': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'passed': passed,
            'score': score,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    })

if __name__ == '__main__':
    app.run(debug=True)