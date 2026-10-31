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

# Usage types that show data being encrypted or destroyed, the two halves of ransomware.
# (marker in the usage type, service, what it means, MITRE technique)
RANSOMWARE_USAGE = [
    ("KMS-Requests", "awskms", "KMS key requests, used to encrypt data", "T1486"),
    ("Requests-Tier1", "AmazonS3", "S3 write and copy requests, used to rewrite objects encrypted", "T1486"),
    ("EarlyDelete", "AmazonS3", "S3 early deletion charges, from deleting stored data in bulk", "T1485"),
]

# Request charges are tiny (a million KMS requests costs about $3), so these rules
# use a lower floor than the $10 used for spend spikes.
RANSOMWARE_MIN_COST = 2.0

# Charge types that are one-off or long-term purchases rather than normal usage.
# Attackers use them to burn money quickly, and they are hard to undo.
RISKY_CHARGE_TYPES = {
    "Fee": "one-off fees such as domain registrations or support plan upgrades",
    "RIFee": "Reserved Instance purchases commit the account to paying for up to 3 years",
    "SavingsPlanUpfrontFee": "upfront Savings Plan purchases can cost thousands at once and can't be cancelled",
}

MARKETPLACE_ENTITY = "AWS Marketplace"

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
    "RANSOMWARE_SIGNAL": "T1486",           # Data Encrypted for Impact (T1485 for deletion)
    "NEW_CHARGE_TYPE": "T1496",             # Resource Hijacking (closest match)
    "NEW_MARKETPLACE_PRODUCT": "T1496.004",  # Cloud Service Hijacking
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
        if row.get("billing_entity") == MARKETPLACE_ENTITY:
            continue  # Marketplace products are handled by find_new_marketplace_products
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


def find_ransomware_signals(baseline, recent, multiplier, min_cost=RANSOMWARE_MIN_COST):
    """A surge in the requests ransomware needs: encrypting with KMS, rewriting or deleting S3 data."""
    findings = []
    for marker, service, meaning, technique in RANSOMWARE_USAGE:
        def matches(row):
            return row["service"] == service and marker in row["usage_type"]

        before = _daily_totals([row for row in baseline if matches(row)], "region")
        after = _daily_totals([row for row in recent if matches(row)], "region")
        for region, day_costs in after.items():
            normal = _average_daily(before.get(region, {}))
            worst_day, worst_cost = max(day_costs.items(), key=lambda item: item[1])
            if worst_cost >= min_cost and (normal == 0 or worst_cost >= normal * multiplier):
                compared = f"{worst_cost / normal:.1f}x the normal ${normal:,.2f}" if normal else "with none before"
                findings.append({
                    "severity": "HIGH",
                    "rule": "RANSOMWARE_SIGNAL",
                    "title": f"Possible ransomware activity in {region}: {meaning.split(',')[0]}",
                    "detail": (f"On {worst_day} {meaning} cost ${worst_cost:,.2f} in {region}, "
                               f"{compared}. Check for objects being re-encrypted with an unknown "
                               "KMS key or deleted in bulk."),
                    "cost": round(sum(day_costs.values()), 2),
                    "mitre": technique,
                })
    return findings


def find_new_charge_types(baseline, recent):
    """A one-off or upfront purchase type that never appeared before, such as a Savings Plan bought outright."""
    known = {row.get("charge_type", "Usage") for row in baseline}
    new_rows = defaultdict(list)
    for row in recent:
        charge_type = row.get("charge_type", "Usage")
        if charge_type in RISKY_CHARGE_TYPES and charge_type not in known and row["cost"] > 0:
            new_rows[charge_type].append(row)

    findings = []
    for charge_type, charge_rows in new_rows.items():
        services = sorted({row["service"] for row in charge_rows})
        findings.append({
            "severity": "HIGH",
            "rule": "NEW_CHARGE_TYPE",
            "title": f"New kind of charge: {charge_type}",
            "detail": (f"The bill has {charge_type} charges for the first time "
                       f"({', '.join(services)}). Watch out: {RISKY_CHARGE_TYPES[charge_type]}. "
                       "Check someone in finance or engineering made this purchase."),
            "cost": _total_cost(charge_rows),
        })
    return findings


def find_new_marketplace_products(baseline, recent, allowed=()):
    """Software bought through AWS Marketplace that was not bought before."""
    known = {row["service"] for row in baseline
             if row.get("billing_entity") == MARKETPLACE_ENTITY} | set(allowed)
    new_rows = defaultdict(list)
    for row in recent:
        if row.get("billing_entity") == MARKETPLACE_ENTITY and row["cost"] > 0 and row["service"] not in known:
            new_rows[row["service"]].append(row)

    findings = []
    for product, product_rows in new_rows.items():
        findings.append({
            "severity": "HIGH",
            "rule": "NEW_MARKETPLACE_PRODUCT",
            "title": f"New AWS Marketplace subscription: {product}",
            "detail": ("Software from another seller is being billed to this account for the first time. "
                       "Attackers subscribe to paid machine images and AI models with stolen keys."),
            "cost": _total_cost(product_rows),
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
    findings += find_ransomware_signals(baseline, recent, multiplier)
    findings += find_new_charge_types(baseline, recent)
    findings += find_new_marketplace_products(baseline, recent, allow.get("services", ()))

    for finding in findings:
        finding.setdefault("mitre", MITRE_TECHNIQUES[finding["rule"]])
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["cost"]))
    return findings
