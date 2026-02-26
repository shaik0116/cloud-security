import json
import boto3
from datetime import datetime

# Connect to SNS to send email alerts
sns = boto3.client('sns', region_name='eu-north-1')

# YOUR SNS TOPIC ARN — paste yours here from Notepad
SNS_TOPIC_ARN = 'arn:aws:sns:eu-north-1:650251715192:security-alerts'

# Suspicious API calls grouped by how dangerous they are
ATTACK_SIGNATURES = {
    'CRITICAL': [
        'DeleteTrail',
        'StopLogging',
        'CreateUser',
        'AttachUserPolicy',
        'DeleteBucket',
        'PutBucketPublicAccessBlock',
    ],
    'HIGH': [
        'ListUsers',
        'ListBuckets',
        'GetSecretValue',
        'CreateAccessKey',
        'DescribeInstances',
    ],
    'MEDIUM': [
        'ConsoleLogin',
        'UpdateAccessKey',
        'DeleteUser',
        'DetachUserPolicy',
    ]
}

# Plain English explanation for each attack
EXPLANATIONS = {
    'DeleteTrail': 'Someone disabled CloudTrail logging. Attackers do this immediately to hide all future actions.',
    'StopLogging': 'All AWS logging has been stopped. Attackers stop logging to become invisible.',
    'CreateUser': 'A new IAM user was created. Attackers create backdoor accounts to keep access even after stolen credentials are revoked.',
    'AttachUserPolicy': 'Admin permissions were attached to a user. This is privilege escalation.',
    'DeleteBucket': 'An S3 bucket was deleted. Data may have been destroyed.',
    'PutBucketPublicAccessBlock': 'S3 public access settings were changed. Private data may be exposed.',
    'ListUsers': 'All IAM users were listed. This is reconnaissance — attacker mapping your account.',
    'ListBuckets': 'All S3 buckets were listed. Attacker is finding where your data lives.',
    'GetSecretValue': 'A secret was retrieved. Passwords or API keys may have been stolen.',
    'CreateAccessKey': 'New access keys were created. Attacker creating persistent access credentials.',
    'ConsoleLogin': 'Someone logged into AWS Console. Check if time and location are expected.',
    'UpdateAccessKey': 'Access key status was changed. Someone is modifying credentials.',
    'DeleteUser': 'An IAM user was deleted. Someone may be covering their tracks.',
    'DetachUserPolicy': 'Permissions were removed from a user.',
}

def get_severity(event_name):
    for severity, actions in ATTACK_SIGNATURES.items():
        if event_name in actions:
            return severity
    return 'LOW'

def get_explanation(event_name):
    return EXPLANATIONS.get(
        event_name,
        f'The API call {event_name} was detected. Review if this action was expected.'
    )

def lambda_handler(event, context):
    # Extract details from the CloudTrail event
    detail     = event.get('detail', {})
    event_name = detail.get('eventName', 'Unknown')
    source_ip  = detail.get('sourceIPAddress', 'Unknown')
    event_time = detail.get('eventTime', 'Unknown')
    aws_region = detail.get('awsRegion', 'Unknown')
    user_agent = detail.get('userAgent', 'Unknown')

    # Figure out WHO triggered this event
    user_identity = detail.get('userIdentity', {})
    identity_type = user_identity.get('type', 'Unknown')

    if identity_type == 'IAMUser':
        who = user_identity.get('userName', 'Unknown User')
    elif identity_type == 'Root':
        who = 'ROOT ACCOUNT'
    elif identity_type == 'AssumedRole':
        arn = user_identity.get('arn', '')
        who = f"Role: {arn.split('/')[-1]}"
    else:
        who = user_identity.get('arn', 'Unknown')

    # Score severity
    severity = get_severity(event_name)

    # Skip LOW severity events
    if severity == 'LOW':
        print(f"Low severity {event_name} — skipping")
        return {'statusCode': 200, 'body': 'Low severity skipped'}

    # Emoji for email subject
    severity_emoji = {
        'CRITICAL': '🚨',
        'HIGH':     '⚠️',
        'MEDIUM':   '📋'
    }.get(severity, '📋')

    # Build the alert email
    alert_message = f"""
{severity_emoji} AWS SECURITY ALERT — {severity}
{'=' * 50}

WHAT HAPPENED:
  Event:    {event_name}
  Who:      {who}
  From IP:  {source_ip}
  When:     {event_time}
  Region:   {aws_region}

WHAT THIS MEANS:
  {get_explanation(event_name)}

WHAT TO DO RIGHT NOW:
  1. Log into AWS Console immediately
  2. Go to CloudTrail and find this user
  3. Check everything they did before and after
  4. If suspicious — revoke their access keys:
     aws iam update-access-key --access-key-id KEY --status Inactive --user-name {who}
  5. If confirmed breach — change all credentials

CloudTrail:
  https://console.aws.amazon.com/cloudtrail/home

Your Automated AWS Security System
{'=' * 50}
"""

    # Send alert to your email via SNS
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f'{severity_emoji} AWS Alert — {severity}: {event_name} by {who}',
        Message=alert_message
    )

    print(f"Alert sent: {severity} — {event_name} by {who} from {source_ip}")

    return {'statusCode': 200, 'body': f'Alert sent for {event_name}'}