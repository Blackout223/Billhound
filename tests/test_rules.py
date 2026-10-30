"""Tests for the detection rules. Run with:  python -m pytest"""

import json
from datetime import date

from hound.report import write_json
from hound.rules import is_data_egress, is_gpu_instance, run_all_rules


def row(day, service="AmazonEC2", region="us-east-1", usage_type="BoxUsage:t3.medium",
        instance_type="t3.medium", cost=20.0, account="111122223333"):
    """Build one fake billing row. Only pass in the parts a test cares about."""
    return {"date": date(2026, 9, day), "account": account, "service": service, "region": region,
            "usage_type": usage_type, "instance_type": instance_type, "cost": cost}


def quiet_month():
    """Fourteen days of the same normal spend."""
    return [row(day) for day in range(1, 15)]


def rules_found(findings):
    return {f["rule"] for f in findings}


def test_quiet_account_has_no_findings():
    assert run_all_rules(quiet_month()) == []


def test_new_region_is_flagged():
    rows = quiet_month() + [row(14, region="sa-east-1")]
    assert "NEW_REGION" in rules_found(run_all_rules(rows))


def test_gpu_instance_is_flagged():
    rows = quiet_month() + [row(14, instance_type="p3.8xlarge", cost=290.0)]
    assert "GPU_INSTANCE" in rules_found(run_all_rules(rows))


def test_high_risk_new_service_is_high_severity():
    rows = quiet_month() + [row(14, service="AmazonBedrock", instance_type="", cost=50.0)]
    finding = next(f for f in run_all_rules(rows) if f["rule"] == "NEW_SERVICE")
    assert finding["severity"] == "HIGH"


def test_spend_spike_is_flagged():
    rows = quiet_month() + [row(14, cost=200.0)]
    assert "SPEND_SPIKE" in rules_found(run_all_rules(rows))


def test_small_wobble_is_not_a_spike():
    rows = quiet_month() + [row(14, cost=25.0)]
    assert "SPEND_SPIKE" not in rules_found(run_all_rules(rows))


def test_egress_spike_is_flagged():
    egress = [row(day, service="AmazonS3", usage_type="DataTransfer-Out-Bytes",
                  instance_type="", cost=3.0) for day in range(1, 15)]
    egress.append(row(14, service="AmazonS3", usage_type="DataTransfer-Out-Bytes",
                      instance_type="", cost=400.0))
    assert "EGRESS_SPIKE" in rules_found(run_all_rules(quiet_month() + egress))


def test_gpu_family_detection():
    assert is_gpu_instance("g4dn.xlarge")
    assert is_gpu_instance("p5.48xlarge")
    assert not is_gpu_instance("t3.medium")
    assert not is_gpu_instance("m5.large")


def test_stopped_cloudtrail_is_flagged():
    trail = [row(day, service="AWSCloudTrail", region="global", usage_type="PaidEventsRecorded",
                 instance_type="", cost=0.5) for day in range(1, 12)]
    assert "SECURITY_SERVICE_STOPPED" in rules_found(run_all_rules(quiet_month() + trail))


def test_running_cloudtrail_is_not_flagged():
    trail = [row(day, service="AWSCloudTrail", region="global", usage_type="PaidEventsRecorded",
                 instance_type="", cost=0.5) for day in range(1, 15)]
    assert "SECURITY_SERVICE_STOPPED" not in rules_found(run_all_rules(quiet_month() + trail))


def test_ssm_is_a_high_risk_new_service():
    rows = quiet_month() + [row(14, service="AWSSystemsManager", instance_type="", cost=15.0)]
    finding = next(f for f in run_all_rules(rows) if f["rule"] == "NEW_SERVICE")
    assert finding["severity"] == "HIGH"


def test_ecs_is_a_high_risk_new_service():
    rows = quiet_month() + [row(14, service="AmazonECS", usage_type="USE1-Fargate-vCPU-Hours:perCPU",
                                instance_type="", cost=40.0)]
    finding = next(f for f in run_all_rules(rows) if f["rule"] == "NEW_SERVICE")
    assert finding["severity"] == "HIGH"


def test_json_report_can_be_read_back(tmp_path):
    rows = quiet_month() + [row(14, region="sa-east-1")]
    output = tmp_path / "report.json"
    write_json(run_all_rules(rows), "test.csv", output)
    report = json.loads(output.read_text())
    assert report["summary"]["high"] == 1
    assert report["findings"][0]["rule"] == "NEW_REGION"


def test_eks_is_a_high_risk_new_service():
    rows = quiet_month() + [row(14, service="AmazonEKS", instance_type="", cost=20.0)]
    finding = next(f for f in run_all_rules(rows) if f["rule"] == "NEW_SERVICE")
    assert finding["severity"] == "HIGH"


def test_new_account_is_flagged():
    rows = quiet_month() + [row(14, account="999988887777")]
    assert "NEW_ACCOUNT" in rules_found(run_all_rules(rows))


def test_allowlist_silences_expected_region_and_account():
    rows = quiet_month() + [row(14, region="eu-west-2", account="999988887777")]
    allow = {"regions": {"eu-west-2"}, "accounts": {"999988887777"}}
    found = rules_found(run_all_rules(rows, allow=allow))
    assert "NEW_REGION" not in found
    assert "NEW_ACCOUNT" not in found


def test_every_finding_has_a_mitre_technique():
    rows = quiet_month() + [row(14, region="sa-east-1", instance_type="p3.8xlarge", cost=290.0)]
    findings = run_all_rules(rows)
    assert findings
    assert all(f["mitre"].startswith("T1") for f in findings)


def test_nat_gateway_and_cross_region_transfer_count_as_egress():
    assert is_data_egress("USE1-NatGateway-Bytes")
    assert is_data_egress("USE1-USW2-AWS-Out-Bytes")
    assert not is_data_egress("TimedStorage-ByteHrs")


def test_lambda_surge_is_high_severity():
    lam = [row(day, service="AWSLambda", usage_type="Lambda-GB-Second", instance_type="", cost=2.0)
           for day in range(1, 15)]
    lam.append(row(14, service="AWSLambda", usage_type="Lambda-GB-Second", instance_type="", cost=60.0))
    finding = next(f for f in run_all_rules(quiet_month() + lam) if f["rule"] == "COMPUTE_SURGE")
    assert finding["severity"] == "HIGH"
