
import json
import boto3
import uuid
from datetime import datetime, timezone
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:686055675086:CloudShieldSecurityAlerts"
TABLE_NAME = "CloudShieldAlerts"

table = dynamodb.Table(TABLE_NAME)


def lambda_handler(event, context):
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        results = []
        alerts = []

        for bucket in buckets:
            name = bucket["Name"]

            try:
                try:
                    config = s3.get_public_access_block(
                        Bucket=name
                    )["PublicAccessBlockConfiguration"]

                    public_block = all([
                        config.get("BlockPublicAcls", False),
                        config.get("IgnorePublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                        config.get("RestrictPublicBuckets", False)
                    ])

                except ClientError as e:
                    if e.response["Error"]["Code"] in [
                        "NoSuchPublicAccessBlockConfiguration",
                        "AccessDenied"
                    ]:
                        public_block = False
                    else:
                        raise

                encryption = s3.get_bucket_encryption(Bucket=name)
                encrypted = bool(
                    encryption.get("ServerSideEncryptionConfiguration")
                )

                status = (
                    "SECURE"
                    if public_block and encrypted
                    else "WARNING"
                )

                results.append({
                    "bucket": name,
                    "public_access_block": public_block,
                    "encryption_enabled": encrypted,
                    "status": status
                })

                if status == "WARNING":
                    alerts.append({
                        "bucket": name,
                        "public_access_block": public_block,
                        "encryption_enabled": encrypted
                    })

            except Exception as e:
                results.append({
                    "bucket": name,
                    "status": "CHECK_FAILED",
                    "error": str(e)
                })

        notifications = []

        for alert in alerts:
            alert_id = str(uuid.uuid4())
            detected_at = datetime.now(timezone.utc).isoformat()

            notification = "FAILED"

            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="CloudShield Security Alert",
                    Message=(
                        "CloudShield Security Warning\n\n"
                        f"Bucket: {alert['bucket']}\n"
                        f"Public Access Block: {alert['public_access_block']}\n"
                        f"Encryption: {alert['encryption_enabled']}\n"
                        f"Detected: {detected_at}"
                    )
                )
                notification = "SENT"

            except Exception as e:
                print("SNS error:", str(e))

            table.put_item(
                Item={
                    "alertId": alert_id,
                    "bucket": alert["bucket"],
                    "publicAccessBlock": alert["public_access_block"],
                    "encryptionEnabled": alert["encryption_enabled"],
                    "severity": "WARNING",
                    "detectedAt": detected_at,
                    "notificationStatus": notification,
                    "alertStatus": "OPEN"
                }
            )

            notifications.append({
                "bucket": alert["bucket"],
                "notification": notification,
                "database": "SAVED"
            })

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "project": "CloudShield",
                "total_buckets": len(buckets),
                "alerts_count": len(alerts),
                "results": results,
                "notifications": notifications
            })
        }

    except Exception as e:
        print("CloudShield error:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
