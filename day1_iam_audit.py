import boto3
from datetime import datetime, timezone

# Connect to AWS services
iam = boto3.client('iam', region_name='eu-west-1')
s3 = boto3.client('s3', region_name='eu-west-1')

print("=" * 55)
print("   AWS SECURITY AUDIT — IAM + S3")
print(f"   Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 55)

# ═══════════════════════════════════════════════════════
# IAM CHECKS
# ═══════════════════════════════════════════════════════

print("\n🔍 CHECK 1: MFA Status for All Users\n")

all_users = iam.list_users()['Users']
mfa_pass = []
mfa_fail = []

for user in all_users:
    username = user['UserName']
    created = user['CreateDate'].strftime('%Y-%m-%d')
    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']

    if len(mfa_devices) == 0:
        mfa_fail.append(username)
        print(f"  ❌ RISK  | {username:<30} | No MFA | Created: {created}")
    else:
        mfa_pass.append(username)
        print(f"  ✅ SAFE  | {username:<30} | MFA OK | Created: {created}")

print("\n🔍 CHECK 2: Access Key Age\n")

old_keys = []

for user in all_users:
    username = user['UserName']
    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

    for key in keys:
        key_status = key['Status']
        key_created = key['CreateDate']
        age_days = (datetime.now(timezone.utc) - key_created).days

        if age_days > 90 and key_status == 'Active':
            old_keys.append(username)
            print(f"  ❌ RISK  | {username:<30} | Key age: {age_days} days")
        elif key_status == 'Active':
            print(f"  ✅ SAFE  | {username:<30} | Key age: {age_days} days")

print("\n🔍 CHECK 3: Root Account MFA\n")

account_summary = iam.get_account_summary()['SummaryMap']
root_mfa = account_summary.get('AccountMFAEnabled', 0)

if root_mfa:
    print(f"  ✅ SAFE  | Root account has MFA enabled")
else:
    print(f"  ❌ RISK  | Root account has NO MFA - Critical!")

print("\n" + "=" * 55)
print("   IAM SUMMARY")
print("=" * 55)
print(f"  Total users scanned : {len(all_users)}")
print(f"  Users WITH MFA      : {len(mfa_pass)} ✅")
print(f"  Users WITHOUT MFA   : {len(mfa_fail)} ❌")
print(f"  Old access keys     : {len(old_keys)} ❌")

if mfa_fail or old_keys:
    print(f"\n  ⚠️  ACTION REQUIRED")
    if mfa_fail:
        print(f"  Enable MFA for : {', '.join(mfa_fail)}")
    if old_keys:
        print(f"  Rotate keys for: {', '.join(set(old_keys))}")
else:
    print(f"\n  ✅ All IAM checks passed!")

# ═══════════════════════════════════════════════════════
# S3 CHECKS
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 55)
print("   S3 BUCKET SECURITY CHECKS")
print("=" * 55)

print("\n🔍 CHECK 4-6: S3 Bucket Security\n")

all_buckets = s3.list_buckets()['Buckets']

if not all_buckets:
    print("  ℹ️  No S3 buckets found in this account.")
else:
    public_buckets = []
    unencrypted_buckets = []
    unlogged_buckets = []

    for bucket in all_buckets:
        bucket_name = bucket['Name']
        created = bucket['CreationDate'].strftime('%Y-%m-%d')

        print(f"\n  📦 Scanning bucket: {bucket_name}")

        # CHECK 4: PUBLIC ACCESS BLOCK
        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            )
            config = public_access['PublicAccessBlockConfiguration']

            all_blocked = all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ])

            if all_blocked:
                print(f"     ✅ Public Access  | Fully blocked")
            else:
                print(f"     ❌ Public Access  | NOT blocked — RISK!")
                public_buckets.append(bucket_name)

        except Exception:
            print(f"     ❌ Public Access  | No block configured — RISK!")
            public_buckets.append(bucket_name)

        # CHECK 5: ENCRYPTION
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption['ServerSideEncryptionConfiguration']['Rules']

            if rules:
                enc_type = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                print(f"     ✅ Encryption     | Enabled ({enc_type})")
            else:
                print(f"     ❌ Encryption     | Not enabled — RISK!")
                unencrypted_buckets.append(bucket_name)

        except Exception:
            print(f"     ❌ Encryption     | Not configured — RISK!")
            unencrypted_buckets.append(bucket_name)

        # CHECK 6: ACCESS LOGGING
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)

            if 'LoggingEnabled' in logging_config:
                log_bucket = logging_config['LoggingEnabled']['TargetBucket']
                print(f"     ✅ Access Logging | Enabled → {log_bucket}")
            else:
                print(f"     ⚠️  Access Logging | Not enabled")
                unlogged_buckets.append(bucket_name)

        except Exception:
            print(f"     ⚠️  Access Logging | Could not check")
            unlogged_buckets.append(bucket_name)

    print("\n" + "=" * 55)
    print("   S3 SUMMARY")
    print("=" * 55)
    print(f"  Total buckets scanned  : {len(all_buckets)}")
    print(f"  Public access risks    : {len(public_buckets)} ❌")
    print(f"  Unencrypted buckets    : {len(unencrypted_buckets)} ❌")
    print(f"  Logging not enabled    : {len(unlogged_buckets)} ⚠️")

    if public_buckets:
        print(f"\n  🚨 CRITICAL — Fix immediately:")
        for b in public_buckets:
            print(f"     → {b} is publicly accessible!")

    if unencrypted_buckets:
        print(f"\n  ⚠️  Enable encryption on:")
        for b in unencrypted_buckets:
            print(f"     → {b}")

    if not public_buckets and not unencrypted_buckets:
        print(f"\n  ✅ All S3 buckets are secure!")

print("\n" + "=" * 55)
print("   FULL AUDIT COMPLETE")
print("=" * 55)