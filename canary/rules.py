"""Detection rules. Each rule looks at the billing rows and returns a list of findings.

A finding is a dictionary:
    {"severity": "HIGH", "rule": "NEW_REGION", "title": "...", "detail": "...", "cost": 123.45}
"""

from collections import defaultdict
from datetime import timedelta

# Instance families with GPUs or ML chips. Crypto-miners and people stealing
# compute for AI love these.
GPU_FAMILIES = ("p2", "p3", "p4", "p5", "g3", "g4", "g5", "g6", "trn", "inf", "dl")

# Services attackers commonly abuse after stealing keys.
HIGH_RISK_SERVICES = {
    "AmazonBedrock": "LLM access is resold by attackers ('LLMjacking')",
    "AmazonSageMaker": "can launch GPU machines outside normal EC2 dashboards",
    "AmazonLightsail": "cheap servers often used for mining or phishing",
    "AmazonSES": "used to send phishing and spam from your domain",
}

# Spending below this many dollars is ignored by the spike rules, so
# tiny services going from $0.01 to $0.05 don't raise alarms.
DEFAULT_MIN_COST = 10.0


def split_periods(rows, recent_days):
    """Split rows into (baseline, recent). Recent is the last `recent_days` days."""
    if not rows:
        return [], []
    last_day = max(row["date"] for row in rows)
    cutoff = last_day - timedelta(days=recent_days - 1)
    baseline = [row for row in rows if row["date"] < cutoff]
    recent = [row for row in rows if row["date"] >= cutoff]
    return baseline, recent


def _total_cost(rows):
    return round(sum(row["cost"] for row in rows), 2)


def find_new_regions(baseline, recent):
    """Spending in a region that had none during the baseline period."""
    known = {row["region"] for row in baseline if row["cost"] > 0}
    new_rows = defaultdict(list)
    for row in recent:
        if row["cost"] > 0 and row["region"] not in known and row["region"] != "global":
            new_rows[row["region"]].append(row)

    findings = []
    for region, region_rows in new_rows.items():
        services = sorted({row["service"] for row in region_rows})
        findings.append({
            "severity": "HIGH",
            "rule": "NEW_REGION",
            "title": f"New region in use: {region}",
            "detail": (f"Spend started in {region}, which had no spend before. "
                       f"Services: {', '.join(services)}. Attackers often hide "
                       "resources in regions nobody watches."),
            "cost": _total_cost(region_rows),
        })
    return findings


def find_new_services(baseline, recent):
    """A service that appears for the first time."""
    known = {row["service"] for row in baseline if row["cost"] > 0}
    new_rows = defaultdict(list)
    for row in recent:
        if row["cost"] > 0 and row["service"] not in known:
            new_rows[row["service"]].append(row)

    findings = []
    for service, service_rows in new_rows.items():
        reason = HIGH_RISK_SERVICES.get(service)
        findings.append({
            "severity": "HIGH" if reason else "MEDIUM",
            "rule": "NEW_SERVICE",
            "title": f"New service in use: {service}",
            "detail": (f"{service} has never been billed before. "
                       + (f"Watch out: {reason}." if reason else "Check that someone expected this.")),
            "cost": _total_cost(service_rows),
        })
    return findings


def is_gpu_instance(instance_type):
    """True for types like 'p3.8xlarge' or 'g5.xlarge'."""
    family = instance_type.split(".")[0].lower()
    # "g4dn" starts with "g4", "trn1" starts with "trn", and so on.
    return family.startswith(GPU_FAMILIES)


def find_gpu_instances(baseline, recent):
    """GPU instance types that were not running during the baseline period."""
    known = {row["instance_type"] for row in baseline if row["instance_type"]}
    new_rows = defaultdict(list)
    for row in recent:
        itype = row["instance_type"]
        if itype and itype not in known and is_gpu_instance(itype):
            new_rows[(itype, row["region"])].append(row)

    findings = []
    for (itype, region), gpu_rows in new_rows.items():
        findings.append({
            "severity": "HIGH",
            "rule": "GPU_INSTANCE",
            "title": f"New GPU instances: {itype} in {region}",
            "detail": ("GPU machines are the favourite target for crypto-mining "
                       "with stolen keys. Confirm a team launched these on purpose."),
            "cost": _total_cost(gpu_rows),
        })
    return findings


def _daily_totals(rows, key):
    """Return {group: {day: cost}} where group is row[key]."""
    totals = defaultdict(lambda: defaultdict(float))
    for row in rows:
        totals[row[key]][row["date"]] += row["cost"]
    return totals


def _average_daily(day_costs):
    return sum(day_costs.values()) / len(day_costs) if day_costs else 0.0


def find_spend_spikes(baseline, recent, multiplier, min_cost=DEFAULT_MIN_COST):
    """A service whose daily spend jumped to `multiplier` times its normal level."""
    before = _daily_totals(baseline, "service")
    after = _daily_totals(recent, "service")

    findings = []
    for service, day_costs in after.items():
        normal = _average_daily(before.get(service, {}))
        if normal == 0:
            continue  # brand new services are handled by find_new_services
        worst_day, worst_cost = max(day_costs.items(), key=lambda item: item[1])
        if worst_cost >= min_cost and worst_cost >= normal * multiplier:
            findings.append({
                "severity": "MEDIUM",
                "rule": "SPEND_SPIKE",
                "title": f"Spend spike: {service}",
                "detail": (f"On {worst_day} {service} cost ${worst_cost:,.2f}, "
                           f"{worst_cost / normal:.1f}x its normal ${normal:,.2f} per day."),
                "cost": round(sum(day_costs.values()), 2),
            })
    return findings


def is_data_egress(usage_type):
    """CUR usage types like 'DataTransfer-Out-Bytes' or 'EUW2-DataTransfer-Out-Bytes' mean data leaving AWS."""
    return "DataTransfer-Out-Bytes" in usage_type


def find_egress_spikes(baseline, recent, multiplier, min_cost=DEFAULT_MIN_COST):
    """Data leaving AWS suddenly costs much more than usual. Can mean data theft."""
    before = [row for row in baseline if is_data_egress(row["usage_type"])]
    after = [row for row in recent if is_data_egress(row["usage_type"])]

    before_daily = _daily_totals(before, "region")
    after_daily = _daily_totals(after, "region")

    findings = []
    for region, day_costs in after_daily.items():
        normal = _average_daily(before_daily.get(region, {}))
        worst_day, worst_cost = max(day_costs.items(), key=lambda item: item[1])
        if worst_cost >= min_cost and (normal == 0 or worst_cost >= normal * multiplier):
            compared = f"{worst_cost / normal:.1f}x the normal ${normal:,.2f}" if normal else "with no egress before"
            findings.append({
                "severity": "HIGH",
                "rule": "EGRESS_SPIKE",
                "title": f"Data transfer out spike in {region}",
                "detail": (f"On {worst_day} data leaving AWS from {region} cost ${worst_cost:,.2f}, "
                           f"{compared}. Large unexpected downloads can mean stolen data."),
                "cost": round(sum(day_costs.values()), 2),
            })
    return findings


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all_rules(rows, recent_days=7, multiplier=3.0, min_cost=DEFAULT_MIN_COST):
    """Run every rule and return findings, most severe and most expensive first."""
    baseline, recent = split_periods(rows, recent_days)
    if not baseline:
        raise ValueError("Not enough history: the file needs more days than --recent-days.")

    findings = []
    findings += find_new_regions(baseline, recent)
    findings += find_new_services(baseline, recent)
    findings += find_gpu_instances(baseline, recent)
    findings += find_spend_spikes(baseline, recent, multiplier, min_cost)
    findings += find_egress_spikes(baseline, recent, multiplier, min_cost)

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["cost"]))
    return findings
