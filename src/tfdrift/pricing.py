"""Approximate monthly cost estimates for common cloud resources.

Prices are on-demand, Linux/default OS, us-east-1, USD, 730 hrs/month.
Used only to surface a cost delta when an instance type or class changes —
not a billing tool. Estimates will differ for reserved/spot pricing,
other regions, or Windows workloads.
"""

from __future__ import annotations

from tfdrift.models import DriftedResource

# {resource_type: {attribute: {value: monthly_usd}}}
_PRICES: dict[str, dict[str, dict[str, float]]] = {
    # EC2 instances
    "aws_instance": {
        "instance_type": {
            # T2
            "t2.nano": 4.09, "t2.micro": 8.47, "t2.small": 16.94,
            "t2.medium": 33.87, "t2.large": 67.74, "t2.xlarge": 135.49,
            "t2.2xlarge": 270.98,
            # T3
            "t3.nano": 3.80, "t3.micro": 7.59, "t3.small": 15.18,
            "t3.medium": 30.37, "t3.large": 60.74, "t3.xlarge": 121.47,
            "t3.2xlarge": 242.94,
            # T3a
            "t3a.nano": 3.38, "t3a.micro": 6.77, "t3a.small": 13.54,
            "t3a.medium": 27.08, "t3a.large": 54.17, "t3a.xlarge": 108.33,
            "t3a.2xlarge": 216.66,
            # M5
            "m5.large": 70.08, "m5.xlarge": 140.16, "m5.2xlarge": 280.32,
            "m5.4xlarge": 560.64, "m5.8xlarge": 1121.28,
            "m5.12xlarge": 1681.92, "m5.16xlarge": 2242.56,
            "m5.24xlarge": 3363.84,
            # M6i
            "m6i.large": 70.08, "m6i.xlarge": 140.16, "m6i.2xlarge": 280.32,
            "m6i.4xlarge": 560.64, "m6i.8xlarge": 1121.28,
            "m6i.12xlarge": 1681.92, "m6i.16xlarge": 2242.56,
            "m6i.24xlarge": 3363.84, "m6i.32xlarge": 4484.48,
            # C5
            "c5.large": 62.05, "c5.xlarge": 124.10, "c5.2xlarge": 248.20,
            "c5.4xlarge": 496.40, "c5.9xlarge": 1116.90,
            "c5.18xlarge": 2233.80,
            # C6i
            "c6i.large": 59.13, "c6i.xlarge": 118.26, "c6i.2xlarge": 236.52,
            "c6i.4xlarge": 473.04, "c6i.8xlarge": 946.08,
            "c6i.12xlarge": 1419.12, "c6i.16xlarge": 1892.16,
            "c6i.24xlarge": 2838.24, "c6i.32xlarge": 3784.32,
            # R5
            "r5.large": 91.25, "r5.xlarge": 182.50, "r5.2xlarge": 365.00,
            "r5.4xlarge": 730.00, "r5.8xlarge": 1460.00,
            "r5.12xlarge": 2190.00, "r5.16xlarge": 2920.00,
            "r5.24xlarge": 4380.00,
            # R6i
            "r6i.large": 91.25, "r6i.xlarge": 182.50, "r6i.2xlarge": 365.00,
            "r6i.4xlarge": 730.00, "r6i.8xlarge": 1460.00,
            "r6i.12xlarge": 2190.00, "r6i.16xlarge": 2920.00,
            "r6i.24xlarge": 4380.00, "r6i.32xlarge": 5840.00,
            # X1e / memory-optimised
            "x1e.xlarge": 604.80, "x1e.2xlarge": 1209.60,
            "x1e.4xlarge": 2419.20, "x1e.8xlarge": 4838.40,
            "x1e.16xlarge": 9676.80, "x1e.32xlarge": 19353.60,
        }
    },
    # RDS instances
    "aws_db_instance": {
        "instance_class": {
            # T3
            "db.t3.micro": 12.41, "db.t3.small": 24.82,
            "db.t3.medium": 49.64, "db.t3.large": 99.28,
            "db.t3.xlarge": 198.56, "db.t3.2xlarge": 397.12,
            # M5
            "db.m5.large": 124.83, "db.m5.xlarge": 249.66,
            "db.m5.2xlarge": 499.32, "db.m5.4xlarge": 998.64,
            "db.m5.8xlarge": 1997.28, "db.m5.12xlarge": 2995.92,
            "db.m5.16xlarge": 3994.56, "db.m5.24xlarge": 5991.84,
            # R5
            "db.r5.large": 175.20, "db.r5.xlarge": 350.40,
            "db.r5.2xlarge": 700.80, "db.r5.4xlarge": 1401.60,
            "db.r5.8xlarge": 2803.20, "db.r5.12xlarge": 4204.80,
            "db.r5.16xlarge": 5606.40, "db.r5.24xlarge": 8409.60,
            # R6g (Graviton)
            "db.r6g.large": 157.68, "db.r6g.xlarge": 315.36,
            "db.r6g.2xlarge": 630.72, "db.r6g.4xlarge": 1261.44,
            "db.r6g.8xlarge": 2522.88, "db.r6g.12xlarge": 3784.32,
            "db.r6g.16xlarge": 5045.76,
        }
    },
    # Aurora instances (same attribute name)
    "aws_rds_cluster_instance": {
        "instance_class": {
            "db.t3.medium": 49.64, "db.t3.large": 99.28,
            "db.r5.large": 175.20, "db.r5.xlarge": 350.40,
            "db.r5.2xlarge": 700.80, "db.r5.4xlarge": 1401.60,
            "db.r5.8xlarge": 2803.20, "db.r5.12xlarge": 4204.80,
            "db.r6g.large": 157.68, "db.r6g.xlarge": 315.36,
            "db.r6g.2xlarge": 630.72, "db.r6g.4xlarge": 1261.44,
        }
    },
    # ElastiCache nodes
    "aws_elasticache_cluster": {
        "node_type": {
            "cache.t3.micro": 12.41, "cache.t3.small": 24.82,
            "cache.t3.medium": 49.64,
            "cache.m5.large": 90.52, "cache.m5.xlarge": 181.04,
            "cache.m5.2xlarge": 362.08, "cache.m5.4xlarge": 724.16,
            "cache.r5.large": 121.18, "cache.r5.xlarge": 242.36,
            "cache.r5.2xlarge": 484.72, "cache.r5.4xlarge": 969.44,
            "cache.r6g.large": 109.06, "cache.r6g.xlarge": 218.12,
            "cache.r6g.2xlarge": 436.24, "cache.r6g.4xlarge": 872.48,
        }
    },
    # EKS managed node groups
    "aws_eks_node_group": {
        "instance_types": {
            "t3.medium": 30.37, "t3.large": 60.74, "t3.xlarge": 121.47,
            "m5.large": 70.08, "m5.xlarge": 140.16, "m5.2xlarge": 280.32,
            "m5.4xlarge": 560.64, "c5.large": 62.05, "c5.xlarge": 124.10,
            "c5.2xlarge": 248.20, "r5.large": 91.25, "r5.xlarge": 182.50,
        }
    },
}

# Map resource types that share price tables with another type
_ALIASES: dict[str, str] = {
    "aws_spot_instance_request": "aws_instance",
}


def _lookup(resource_type: str, attribute: str, value: object) -> float | None:
    rtype = _ALIASES.get(resource_type, resource_type)
    attr_prices = _PRICES.get(rtype, {}).get(attribute)
    if not attr_prices or not isinstance(value, str):
        return None
    # Handle Terraform lists like ["m5.large"]
    val = value.strip("[]\"' ")
    return attr_prices.get(val)


def estimate_cost_delta(resource: DriftedResource) -> float | None:
    """Return the estimated monthly cost delta (new - old) for a drifted resource.

    Returns None when pricing data isn't available for this resource/change.
    """
    for change in resource.changes:
        old_price = _lookup(resource.resource_type, change.attribute, change.old_value)
        new_price = _lookup(resource.resource_type, change.attribute, change.new_value)
        if old_price is not None and new_price is not None:
            return round(new_price - old_price, 2)
    return None


def format_cost_delta(delta: float | None) -> str:
    """Format a cost delta as a human-readable string."""
    if delta is None:
        return "—"
    sign = "+" if delta >= 0 else ""
    return f"{sign}${delta:,.0f}/mo"
