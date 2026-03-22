"""Testes unitários para os scanners e o risk scorer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scanners.base import Finding, FindingCategory, Severity
from scanners.aws.sg_scanner import AWSSGScanner
from scoring.risk_scorer import build_report, calculate_score


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_finding(severity: Severity, cloud: str = "aws", region: str = "us-east-1") -> Finding:
    return Finding(
        id=f"TEST-{severity.value}-001",
        cloud=cloud,
        region=region,
        resource_id="sg-12345",
        resource_name="test-sg",
        resource_type="security_group",
        category=FindingCategory.NETWORK_EXPOSURE,
        severity=severity,
        title=f"Test finding {severity.value}",
        description="Test description",
        remediation="Test remediation",
    )


# ── Score Tests ───────────────────────────────────────────────────────────────

def test_calculate_score_no_findings() -> None:
    assert calculate_score([]) == 100


def test_calculate_score_single_critical() -> None:
    findings = [make_finding(Severity.CRITICAL)]
    assert calculate_score(findings) == 80  # 100 - 20


def test_calculate_score_multiple_findings() -> None:
    findings = [
        make_finding(Severity.CRITICAL),  # -20
        make_finding(Severity.HIGH),       # -10
        make_finding(Severity.MEDIUM),     # -5
        make_finding(Severity.LOW),        # -2
    ]
    assert calculate_score(findings) == 63  # 100 - 37


def test_calculate_score_never_below_zero() -> None:
    findings = [make_finding(Severity.CRITICAL)] * 10  # -200
    assert calculate_score(findings) == 0


def test_build_report_classification() -> None:
    findings = [make_finding(Severity.CRITICAL)] * 3  # score = 40
    report = build_report(findings, "2024-01-01T00:00:00", ["aws"], ["us-east-1"])
    assert report.global_score == 40
    assert report.global_classification == "Alto Risco"


def test_build_report_summary_by_severity() -> None:
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
    ]
    report = build_report(findings, "2024-01-01T00:00:00", ["aws"], ["us-east-1"])
    assert report.summary_by_severity["CRITICAL"] == 2
    assert report.summary_by_severity["HIGH"] == 1
    assert report.summary_by_severity["MEDIUM"] == 0


# ── SG Scanner Tests ──────────────────────────────────────────────────────────

@patch("scanners.aws.sg_scanner.boto3.client")
def test_sg_scanner_detects_ssh_open(mock_boto: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_boto.return_value = mock_ec2

    mock_paginator = MagicMock()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{
        "SecurityGroups": [{
            "GroupId": "sg-critical001",
            "GroupName": "my-insecure-sg",
            "VpcId": "vpc-12345",
            "Tags": [{"Key": "env", "Value": "production"}],
            "IpPermissions": [{
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
        }]
    }]

    scanner = AWSSGScanner(region="us-east-1")
    findings = scanner.scan_security_groups()

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "22" in findings[0].title
    assert "SSH" in findings[0].title
    assert findings[0].resource_id == "sg-critical001"


@patch("scanners.aws.sg_scanner.boto3.client")
def test_sg_scanner_ignores_restricted_cidrs(mock_boto: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_boto.return_value = mock_ec2

    mock_paginator = MagicMock()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{
        "SecurityGroups": [{
            "GroupId": "sg-safe001",
            "GroupName": "safe-sg",
            "VpcId": "vpc-12345",
            "Tags": [],
            "IpPermissions": [{
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],   # CIDR interno — não deve disparar
                "Ipv6Ranges": [],
            }],
        }]
    }]

    scanner = AWSSGScanner(region="us-east-1")
    findings = scanner.scan_security_groups()

    assert len(findings) == 0


@patch("scanners.aws.sg_scanner.boto3.client")
def test_sg_scanner_detects_all_traffic_rule(mock_boto: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_boto.return_value = mock_ec2

    mock_paginator = MagicMock()
    mock_ec2.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{
        "SecurityGroups": [{
            "GroupId": "sg-alltraffic",
            "GroupName": "dangerous-sg",
            "VpcId": "vpc-99999",
            "Tags": [],
            "IpPermissions": [{
                "IpProtocol": "-1",         # All traffic
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }],
        }]
    }]

    scanner = AWSSGScanner(region="us-east-1")
    findings = scanner.scan_security_groups()

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "TODO" in findings[0].title
