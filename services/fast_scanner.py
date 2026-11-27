"""Fast focused cloud security checks for live AWS auditing."""

import logging
import time
from datetime import datetime, timezone
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

FAST_CONFIG = BotoConfig(
    connect_timeout=15,
    read_timeout=15,
    retries={"total_max_attempts": 2},
)


def audit_aws_account(creds, default_region="us-east-1", time_budget=45):
    """Audit a focused AWS baseline, stopping before the one-minute target."""
    started = time.monotonic()
    deadline = started + time_budget

    def in_budget():
        return time.monotonic() < deadline

    kwargs = dict(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name=default_region,
    )
    if creds.get("session_token"):
        kwargs["aws_session_token"] = creds["session_token"]
    session = boto3.Session(**kwargs)
    if creds.get("role_arn"):
        if not in_budget():
            return [_time_limit_finding()]
        sts = session.client("sts", config=FAST_CONFIG)
        assumed = sts.assume_role(RoleArn=creds["role_arn"], RoleSessionName="CloudAuditQuickScan",
                                  DurationSeconds=900)["Credentials"]
        session = boto3.Session(aws_access_key_id=assumed["AccessKeyId"],
                                aws_secret_access_key=assumed["SecretAccessKey"],
                                aws_session_token=assumed["SessionToken"],
                                region_name=default_region)
    findings = []
    
    # --- 1. IAM Audit ---
    try:
        if not in_budget():
            raise TimeoutError
        iam = session.client("iam", config=FAST_CONFIG)
        
        # 1.1 Root MFA
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            root_mfa = summary.get("AccountMFAEnabled", 0) == 1
            findings.append({
                "check_id": "iam_root_mfa_enabled",
                "title": "Root account has MFA enabled",
                "severity": "critical",
                "status": "PASS" if root_mfa else "FAIL",
                "service": "iam",
                "region": "global",
                "resource": "aws:root",
                "detail": "Root MFA is active." if root_mfa else "The root account does not have Multi-Factor Authentication enabled.",
                "remediation": "Enable MFA on your AWS root account via IAM Console immediately.",
            })
        except Exception as e:
            logger.warning(f"Root MFA check error: {e}")

        # 1.2 User MFA & Access Keys
        try:
            users = iam.list_users().get("Users", [])
            for u in users:
                if not in_budget():
                    break
                uname = u["UserName"]
                arn = u["Arn"]
                
                # MFA check
                mfas = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                if not in_budget():
                    break
                has_mfa = len(mfas) > 0
                findings.append({
                    "check_id": "iam_user_mfa_enabled",
                    "title": f"IAM user {uname} has MFA enabled",
                    "severity": "high",
                    "status": "PASS" if has_mfa else "FAIL",
                    "service": "iam",
                    "region": "global",
                    "resource": arn,
                    "detail": f"User {uname} has {len(mfas)} active MFA device(s)." if has_mfa else f"User {uname} has console/API access but no MFA configured.",
                    "remediation": f"Assign a virtual or hardware MFA device to IAM user {uname}.",
                })

                # Key age check
                keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                now = datetime.now(timezone.utc)
                for k in keys:
                    key_id = k["AccessKeyId"]
                    create_date = k["CreateDate"]
                    age_days = (now - create_date).days
                    is_old = age_days > 90
                    findings.append({
                        "check_id": "iam_access_key_rotation",
                        "title": f"Access key {key_id[:6]}... rotated within 90 days",
                        "severity": "medium",
                        "status": "FAIL" if is_old else "PASS",
                        "service": "iam",
                        "region": "global",
                        "resource": f"{arn}/key/{key_id}",
                        "detail": f"Key {key_id} is {age_days} days old ({k['Status']})." if is_old else f"Key {key_id} is {age_days} days old.",
                        "remediation": "Rotate access keys older than 90 days to prevent credential compromise.",
                    })
        except Exception as e:
            logger.warning(f"User audit error: {e}")

        # 1.3 Password Policy
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            length = policy.get("MinimumPasswordLength", 0)
            strong = (length >= 14 and policy.get("RequireSymbols", False) and policy.get("RequireNumbers", False))
            findings.append({
                "check_id": "iam_password_policy_strong",
                "title": "Account password policy meets security baseline",
                "severity": "low",
                "status": "PASS" if strong else "FAIL",
                "service": "iam",
                "region": "global",
                "resource": "aws:iam:password_policy",
                "detail": f"Min length: {length}, Symbols: {policy.get('RequireSymbols')}, Numbers: {policy.get('RequireNumbers')}." if policy else "No custom password policy configured.",
                "remediation": "Set password minimum length to 14+ characters, requiring uppercase, lowercase, numbers, and symbols.",
            })
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                findings.append({
                    "check_id": "iam_password_policy_strong",
                    "title": "Account password policy meets security baseline",
                    "severity": "low",
                    "status": "FAIL",
                    "service": "iam",
                    "region": "global",
                    "resource": "aws:iam:password_policy",
                    "detail": "No custom IAM password policy exists for this account.",
                    "remediation": "Configure an account-wide IAM password policy enforcing 14+ characters and symbol requirements.",
                })
    except Exception as e:
        logger.error(f"IAM client error: {e}")

    # --- 2. S3 Audit ---
    try:
        if not in_budget():
            raise TimeoutError
        s3 = session.client("s3", config=FAST_CONFIG)
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            findings.append({
                "check_id": "s3_bucket_public_access",
                "title": "S3 buckets public access restriction",
                "severity": "high",
                "status": "PASS",
                "service": "s3",
                "region": default_region,
                "resource": "aws:s3:account",
                "detail": "No S3 buckets found in account. Attack surface is clean.",
                "remediation": "Ensure Block Public Access remains enabled when creating new buckets.",
            })
        else:
            for b in buckets:
                if not in_budget():
                    break
                bname = b["Name"]
                try:
                    pab = s3.get_public_access_block(Bucket=bname).get("PublicAccessBlockConfiguration", {})
                    all_blocked = (pab.get("BlockPublicAcls") and pab.get("IgnorePublicAcls") and
                                   pab.get("BlockPublicPolicy") and pab.get("RestrictPublicBuckets"))
                    findings.append({
                        "check_id": "s3_bucket_public_access",
                        "title": f"S3 bucket {bname} has Block Public Access enabled",
                        "severity": "high",
                        "status": "PASS" if all_blocked else "FAIL",
                        "service": "s3",
                        "region": default_region,
                        "resource": f"arn:aws:s3:::{bname}",
                        "detail": f"Public access block settings for {bname}: {pab}",
                        "remediation": f"Enable all four Block Public Access settings on bucket {bname}.",
                    })
                except ClientError:
                    findings.append({
                        "check_id": "s3_bucket_public_access",
                        "title": f"S3 bucket {bname} has Block Public Access enabled",
                        "severity": "high",
                        "status": "FAIL",
                        "service": "s3",
                        "region": default_region,
                        "resource": f"arn:aws:s3:::{bname}",
                        "detail": f"Bucket {bname} has no Public Access Block configuration.",
                        "remediation": f"Enable Block Public Access on bucket {bname}.",
                    })

                try:
                    s3.get_bucket_encryption(Bucket=bname)
                    findings.append({
                        "check_id": "s3_bucket_default_encryption",
                        "title": f"S3 bucket {bname} default encryption enabled",
                        "severity": "medium",
                        "status": "PASS",
                        "service": "s3",
                        "region": default_region,
                        "resource": f"arn:aws:s3:::{bname}",
                        "detail": f"Default encryption configured for {bname}.",
                        "remediation": "",
                    })
                except ClientError:
                    findings.append({
                        "check_id": "s3_bucket_default_encryption",
                        "title": f"S3 bucket {bname} default encryption enabled",
                        "severity": "medium",
                        "status": "FAIL",
                        "service": "s3",
                        "region": default_region,
                        "resource": f"arn:aws:s3:::{bname}",
                        "detail": f"Bucket {bname} does not have server-side default encryption configured.",
                        "remediation": f"Enable default server-side encryption with SSE-S3 or AWS KMS on bucket {bname}.",
                    })
    except Exception as e:
        logger.error(f"S3 client error: {e}")

    # --- 3. EC2 & VPC Security Groups ---
    try:
        if not in_budget():
            raise TimeoutError
        ec2 = session.client("ec2", config=FAST_CONFIG)
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            if not in_budget():
                break
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            open_ssh = False
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                has_any_ip = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                if has_any_ip and from_port <= 22 <= to_port:
                    open_ssh = True

            findings.append({
                "check_id": "network_ssh_open_world",
                "title": f"Security group {sg_name} ({sg_id}) closes SSH port 22 to 0.0.0.0/0",
                "severity": "high",
                "status": "FAIL" if open_ssh else "PASS",
                "service": "network",
                "region": default_region,
                "resource": f"arn:aws:ec2:{default_region}::security-group/{sg_id}",
                "detail": f"Port 22 (SSH) is exposed to 0.0.0.0/0 in {sg_name}." if open_ssh else f"SSH port 22 is restricted in {sg_name}.",
                "remediation": f"Remove 0.0.0.0/0 inbound rules for port 22 from security group {sg_id} and restrict to trusted CIDRs.",
            })

        # EBS default encryption
        try:
            ebs_enc = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
            findings.append({
                "check_id": "encryption_at_rest",
                "title": f"EBS default encryption enabled in {default_region}",
                "severity": "medium",
                "status": "PASS" if ebs_enc else "FAIL",
                "service": "compute",
                "region": default_region,
                "resource": f"aws:ec2:{default_region}:ebs",
                "detail": "EBS volumes are automatically encrypted." if ebs_enc else "EBS encryption by default is disabled.",
                "remediation": f"Enable EBS default encryption in region {default_region}.",
            })
        except Exception:
            pass
    except Exception as e:
        logger.error(f"EC2 client error: {e}")

    # --- 4. CloudTrail Audit ---
    try:
        if not in_budget():
            raise TimeoutError
        ct = session.client("cloudtrail", config=FAST_CONFIG)
        trails = ct.describe_trails().get("trailList", [])
        has_logging = False
        for t in trails:
            if not in_budget():
                break
            try:
                st = ct.get_trail_status(Name=t["TrailARN"])
                if st.get("IsLogging", False):
                    has_logging = True
                    break
            except Exception:
                pass
        findings.append({
            "check_id": "logging_enabled",
            "title": "Audit logging with AWS CloudTrail is active",
            "severity": "high",
            "status": "PASS" if has_logging else "FAIL",
            "service": "logging",
            "region": default_region,
            "resource": "aws:cloudtrail:trails",
            "detail": "At least one active CloudTrail trail is logging events." if has_logging else "No active CloudTrail trail was found logging API activity.",
            "remediation": "Create and enable a multi-region CloudTrail trail sending events to an encrypted S3 bucket.",
        })
    except Exception as e:
        logger.error(f"CloudTrail client error: {e}")

    return findings



