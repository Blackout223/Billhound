"""Detection rules. Each rule looks at the billing rows and returns a list of findings.

A finding is a dictionary:
    {"severity": "HIGH", "rule": "NEW_REGION", "title": "...", "detail": "...", "cost": 123.45,
     "mitre": "T1535"}
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
    "AWSSystemsManager": "can run commands on servers without SSH, a known command-and-control route",
    "AmazonRoute53": "new domains or DNS changes can be used for phishing or traffic redirection",
    "AmazonECS": "Fargate containers are a common way to run crypto-miners without managing servers",
    "AmazonEKS": "Kubernetes clusters let attackers hide mining pods among normal workloads",
}

# Services where a sudden cost surge is HIGH rather than MEDIUM, because attackers use
# them for cheap, hard-to-spot compute.
SURGE_SERVICES = {
    "AWSLambda": "thousands of short functions can be used for mining or mass scanning",
}

# The MITRE ATT&CK technique each rule maps to (https://attack.mitre.org).
MITRE_TECHNIQUES = {
    "NEW_REGION": "T1535",                  # Unused/Unsupported Cloud Regions
    "NEW_ACCOUNT": "T1496",                 # Resource Hijacking
    "NEW_SERVICE": "T1496.004",             # Cloud Service Hijacking
    "GPU_INSTANCE": "T1496.001",            # Compute Hijacking
    "SECURITY_SERVICE_STOPPED": "T1562.008",  # Disable or Modify Cloud Logs
    "SPEND_SPIKE": "T1496",                 # Resource Hijacking
    "COMPUTE_SURGE": "T1496.001",           # Compute Hijacking
    "EGRESS_SPIKE": "T1530",                # Data from Cloud Storage
}

# Logging and detection services. If one of these stops being billed, someone
# may have switched it off to hide what they are doing.
SECURITY_SERVICES = {
    "AWSCloudTrail": "audit logging",
    "AmazonGuardDuty": "threat detection",
    "AWSConfig": "configuration recording",
    "AWSSecurityHub": "security findings",
}

# How many of the latest days a security service must be silent before we flag it.
QUIET_DAYS = 2

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


def find_new_regions(baseline, recent, allowed=()):
    """Spending in a region that had none during the baseline period."""
    known = {row["region"] for row in baseline if row["cost"] > 0} | set(allowed)
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


def find_new_accounts(baseline, recent, allowed=()):
    """Spending in an AWS account that had none during the baseline period."""
    known = {row["account"] for row in baseline if row["cost"] > 0} | set(allowed)
    new_rows = defaultdict(list)
    for row in recent:
        if row["cost"] > 0 and row["account"] not in known and row["account"] != "unknown":
            new_rows[row["account"]].append(row)

    findings = []
    for account, account_rows in new_rows.items():
        services = sorted({row["service"] for row in account_rows})
        findings.append({
            "severity": "HIGH",
            "rule": "NEW_ACCOUNT",
            "title": f"New account with spend: {account}",
            "detail": (f"Account {account} had no spend before. Services: {', '.join(services)}. "
                       "Attackers with organisation access create or reuse quiet accounts "
                       "because nobody is watching them."),
            "cost": _total_cost(account_rows),
        })
    return findings


def find_new_services(baseline, recent, allowed=()):
    """A service that appears for the first time."""
    known = {row["service"] for row in baseline if row["cost"] > 0} | set(allowed)
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


def find_stopped_security_services(baseline, recent, quiet_days=QUIET_DAYS):
    """A logging or detection service that was billed before but has gone silent."""
    last_day = max(row["date"] for row in recent)
    quiet_from = last_day - timedelta(days=quiet_days - 1)
    billed_before = {row["service"] for row in baseline if row["cost"] > 0}
    billed_lately = {row["service"] for row in recent
                     if row["date"] >= quiet_from and row["cost"] > 0}

    findings = []
    for service, purpose in SECURITY_SERVICES.items():
        if service in billed_before and service not in billed_lately:
            findings.append({
                "severity": "HIGH",
                "rule": "SECURITY_SERVICE_STOPPED",
                "title": f"Security service went silent: {service}",
                "detail": (f"{service} ({purpose}) was billed before but not in the last "
                           f"{quiet_days} days. Attackers switch off logging and detection "
                           "to hide their activity. Check it is still enabled."),
                "cost": 0.0,
            })
    return findings


def is_gpu_instance(instance_type):
    """True for types like 'p3.8xlarge' or 'g5.xlarge'."""
    family = instance_type.split(".")[0].lower()
    # "g4dn" starts with "g4", "trn1" starts with "trn", and so on.
    return family.startswith(GPU_FAMILIES)


def find_gpu_instances(baseline, recent, allowed=()):
    """GPU instance types that were not running during the baseline period."""
    known = {row["instance_type"] for row in baseline if row["instance_type"]} | set(allowed)
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
            reason = SURGE_SERVICES.get(service)
            findings.append({
                "severity": "HIGH" if reason else "MEDIUM",
                "rule": "COMPUTE_SURGE" if reason else "SPEND_SPIKE",
                "title": f"{'Compute surge' if reason else 'Spend spike'}: {service}",
                "detail": (f"On {worst_day} {service} cost ${worst_cost:,.2f}, "
                           f"{worst_cost / normal:.1f}x its normal ${normal:,.2f} per day."
                           + (f" Watch out: {reason}." if reason else "")),
                "cost": round(sum(day_costs.values()), 2),
            })
    return findings


# Usage type endings that mean data is moving out:
#   DataTransfer-Out-Bytes   to the internet, e.g. "EUW2-DataTransfer-Out-Bytes"
#   AWS-Out-Bytes            to another AWS region, e.g. "USE1-USW2-AWS-Out-Bytes"
#   NatGateway-Bytes         through a NAT gateway, the usual route out of a private network
EGRESS_USAGE_TYPES = ("DataTransfer-Out-Bytes", "AWS-Out-Bytes", "NatGateway-Bytes")


def is_data_egress(usage_type):
    """True when a usage type means data leaving a region: internet, cross-region or NAT gateway."""
    return any(marker in usage_type for marker in EGRESS_USAGE_TYPES)


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
                "detail": (f"On {worst_day} data transfer out of {region} cost ${worst_cost:,.2f}, "
                           f"{compared}. Large unexpected transfers to the internet, another "
                           "region or through a NAT gateway can mean stolen data."),
                "cost": round(sum(day_costs.values()), 2),
            })
    return findings


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all_rules(rows, recent_days=7, multiplier=3.0, min_cost=DEFAULT_MIN_COST, allow=None):
    """Run every rule and return findings, most severe and most expensive first.

    `allow` is an optional allowlist (see loader.load_allowlist): regions, services,
    instance types and accounts listed there are treated as expected.
    """
    allow = allow or {}
    baseline, recent = split_periods(rows, recent_days)
    if not baseline:
        raise ValueError("Not enough history: the file needs more days than --recent-days.")

    findings = []
    findings += find_new_regions(baseline, recent, allow.get("regions", ()))
    findings += find_new_accounts(baseline, recent, allow.get("accounts", ()))
    findings += find_new_services(baseline, recent, allow.get("services", ()))
    findings += find_gpu_instances(baseline, recent, allow.get("instance_types", ()))
    findings += find_stopped_security_services(baseline, recent)
    findings += find_spend_spikes(baseline, recent, multiplier, min_cost)
    findings += find_egress_spikes(baseline, recent, multiplier, min_cost)

    for finding in findings:
        finding["mitre"] = MITRE_TECHNIQUES[finding["rule"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["cost"]))
    return findings
