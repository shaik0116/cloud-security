import boto3
import json

sns = boto3.client("sns", region_name="eu-north-1")

SNS_TOPIC_ARN = "arn:aws:sns:eu-north-1:650251715192:security-alerts"

ATTACK_SIGNATURES = {
    "CRITICAL": [
        "DeleteTrail",
        "StopLogging",
        "CreateUser",
        "AttachUserPolicy",
        "DeleteBucket",
    ],
    "HIGH": [
        "ListUsers",
        "ListBuckets",
        "GetSecretValue",
        "CreateAccessKey",
    ],
    "MEDIUM": [
        "ConsoleLogin",
        "UpdateAccessKey",
        "DeleteUser",
    ],
}

EXPLANATIONS = {
    "DeleteTrail": "Attacker disabled CloudTrail to hide their tracks.",
    "StopLogging": "All AWS logging stopped. Attacker is becoming invisible.",
    "CreateUser": "New IAM user created. Attacker creating backdoor account.",
    "AttachUserPolicy": "Admin permissions attached. Privilege escalation detected.",
    "DeleteBucket": "S3 bucket deleted. Data may have been destroyed.",
    "ListUsers": "All IAM users listed. Attacker mapping your account.",
    "ListBuckets": "All S3 buckets listed. Attacker looking for data.",
    "GetSecretValue": "Secret retrieved. Passwords or API keys may be stolen.",
    "CreateAccessKey": "New access keys created. Attacker creating persistent access.",
    "ConsoleLogin": "Someone logged into AWS Console. Check if this is expected.",
    "UpdateAccessKey": "Access key modified. Someone changing credentials.",
    "DeleteUser": "IAM user deleted. Someone may be covering their tracks.",
}


def get_severity(event_name: str) -> str:
    for severity, actions in ATTACK_SIGNATURES.items():
        if event_name in actions:
            return severity
    return "LOW"


def get_explanation(event_name: str) -> str:
    return EXPLANATIONS.get(
        event_name, f"API call {event_name} detected. Review if this was expected."
    )


def lambda_handler(event, context):
    detail = event.get("detail", {}) or {}

    event_name = detail.get("eventName", "Unknown")
    source_ip = detail.get("sourceIPAddress", "Unknown")
    event_time = detail.get("eventTime", "Unknown")
    aws_region = detail.get("awsRegion", "Unknown")
    user_agent = detail.get("userAgent", "Unknown")

    user_identity = detail.get("userIdentity", {}) or {}
    identity_type = user_identity.get("type", "Unknown")

    # Determine "who"
    if identity_type == "IAMUser":
        who = user_identity.get("userName", "Unknown")
    elif identity_type == "Root":
        who = "ROOT ACCOUNT"
    elif identity_type == "AssumedRole":
        arn = user_identity.get("arn", "") or ""
        role_name = arn.split("/")[-1] if "/" in arn else arn
        who = f"Role: {role_name or 'Unknown'}"
    else:
        who = user_identity.get("arn") or user_identity.get("principalId") or "Unknown"

    severity = get_severity(event_name)

    if severity == "LOW":
        print(f"Low severity {event_name} — skipping")
        return {"statusCode": 200, "body": "Low severity skipped"}

    severity_emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📋"}.get(severity, "📋")
    explanation = get_explanation(event_name)

    # Build alert message (FIXED: properly closed string)
    alert_message = f"""
{severity_emoji} AWS SECURITY ALERT — {severity}
{'=' * 60}
Event:      {event_name}
Who:        {who} ({identity_type})
Source IP:  {source_ip}
Time:       {event_time}
Region:     {aws_region}
UserAgent:  {user_agent}

Why this matters:
- {explanation}

Raw event (detail):
{json.dumps(detail, indent=2)}
""".strip()

    subject = f"{severity} AWS Alert: {event_name}"

    try:
        resp = sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=alert_message)
        print(f"SNS published, MessageId={resp.get('MessageId')}")
        return {"statusCode": 200, "body": "Alert sent"}
    except Exception as e:
        # Don't crash Lambda without a clear log message
        print(f"ERROR publishing to SNS: {e}")
        return {"statusCode": 500, "body": "Failed to send alert"}