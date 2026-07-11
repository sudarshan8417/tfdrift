"""CloudTrail blame — answer 'who changed this?' after drift is detected.

Queries AWS CloudTrail to find the most recent API event that touched a
drifted resource. Requires boto3 (pip install tfdrift[aws]) and AWS
credentials configured in the environment (IAM role, ~/.aws/credentials,
or environment variables).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# How far back to search CloudTrail (max 90 days for standard trails)
DEFAULT_LOOKBACK_DAYS = 7


@dataclass
class BlameResult:
    """Who last changed a resource according to CloudTrail."""

    resource_address: str
    event_name: str
    event_time: str
    actor: str
    source_ip: str
    region: str
    event_id: str

    def to_dict(self) -> dict:
        return {
            "resource_address": self.resource_address,
            "event_name": self.event_name,
            "event_time": self.event_time,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "region": self.region,
            "event_id": self.event_id,
        }


def _resource_name_from_address(address: str) -> str:
    """Extract the bare resource name from a Terraform address.

    aws_instance.web           -> web
    module.vpc.aws_instance.db -> db
    """
    parts = address.split(".")
    return parts[-1]


# Map Terraform resource types to the CloudTrail resource type string
# used in the Resources field of CloudTrail events.
_RESOURCE_TYPE_MAP: dict[str, str] = {
    "aws_instance": "AWS::EC2::Instance",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_security_group_rule": "AWS::EC2::SecurityGroup",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_route_table": "AWS::EC2::RouteTable",
    "aws_internet_gateway": "AWS::EC2::InternetGateway",
    "aws_network_acl": "AWS::EC2::NetworkAcl",
    "aws_network_acl_rule": "AWS::EC2::NetworkAcl",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_s3_bucket_policy": "AWS::S3::Bucket",
    "aws_s3_bucket_public_access_block": "AWS::S3::Bucket",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_policy": "AWS::IAM::ManagedPolicy",
    "aws_iam_role_policy": "AWS::IAM::Role",
    "aws_iam_user": "AWS::IAM::User",
    "aws_iam_user_policy": "AWS::IAM::User",
    "aws_iam_group": "AWS::IAM::Group",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_rds_instance": "AWS::RDS::DBInstance",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_eks_cluster": "AWS::EKS::Cluster",
    "aws_eks_node_group": "AWS::EKS::Nodegroup",
    "aws_elasticache_cluster": "AWS::ElastiCache::CacheCluster",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_cloudfront_distribution": "AWS::CloudFront::Distribution",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
}


def _get_actor(event: dict) -> str:
    """Extract a human-readable actor from a CloudTrail event."""
    identity = event.get("userIdentity", {})
    id_type = identity.get("type", "")
    if id_type == "IAMUser":
        return identity.get("userName", "unknown-iam-user")
    if id_type == "AssumedRole":
        arn = identity.get("arn", "")
        # arn:aws:sts::123:assumed-role/RoleName/SessionName
        parts = arn.split("/")
        if len(parts) >= 3:
            return f"{parts[-2]}/{parts[-1]}"
        return arn
    if id_type == "Root":
        return "root"
    if id_type == "AWSService":
        return identity.get("invokedBy", "aws-service")
    return identity.get("arn", identity.get("principalId", "unknown"))


def lookup_blame(
    resource_address: str,
    resource_type: str,
    region: str | None = None,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    profile: str | None = None,
) -> BlameResult | None:
    """Query CloudTrail for the most recent event touching this resource.

    Args:
        resource_address: Terraform full address (e.g. aws_instance.web).
        resource_type: Terraform resource type (e.g. aws_instance).
        region: AWS region to query. Defaults to boto3 default.
        lookback_days: How many days back to search (max 90).
        profile: AWS profile name. Uses default credential chain if None.

    Returns:
        BlameResult if an event was found, None otherwise.
    """
    try:
        import boto3
    except ImportError:
        logger.warning(
            "boto3 is required for blame. Install with: pip install tfdrift[aws]"
        )
        return None

    ct_resource_type = _RESOURCE_TYPE_MAP.get(resource_type)
    if not ct_resource_type:
        logger.debug("No CloudTrail resource type mapping for %s", resource_type)
        return None

    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        client = session.client("cloudtrail")
        resolved_region = session.region_name or "us-east-1"

        start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        resource_name = _resource_name_from_address(resource_address)

        paginator = client.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_name},
            ],
            StartTime=start_time,
            EndTime=datetime.now(timezone.utc),
        )

        for page in pages:
            for event in page.get("Events", []):
                # Filter by resource type when CloudTrail provides resource info
                resources = event.get("Resources") or []
                type_match = any(
                    r.get("ResourceType") == ct_resource_type for r in resources
                ) if resources else True  # no resource info — trust name match

                if not type_match:
                    continue

                return BlameResult(
                    resource_address=resource_address,
                    event_name=event.get("EventName", "unknown"),
                    event_time=event["EventTime"].isoformat(),
                    actor=_get_actor(
                        event.get("CloudTrailEvent")
                        and __import__("json").loads(event["CloudTrailEvent"])
                        or {}
                    ),
                    source_ip=__import__("json").loads(
                        event.get("CloudTrailEvent") or "{}"
                    ).get("sourceIPAddress", "—"),
                    region=resolved_region,
                    event_id=event.get("EventId", ""),
                )

    except Exception as e:
        logger.debug("CloudTrail lookup failed for %s: %s", resource_address, e)

    return None
