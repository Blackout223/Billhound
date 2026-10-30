# BillHound report: `sample_data/compromised_month.csv`

| Severity | Finding | Recent cost | MITRE ATT&CK | Details |
|---|---|---:|---|---|
| HIGH | New region in use: sa-east-1 | $1,497.35 | [T1535](https://attack.mitre.org/techniques/T1535/) | Spend started in sa-east-1, which had no spend before. Services: AmazonEC2. Attackers often hide resources in regions nobody watches. |
| HIGH | New GPU instances: p3.8xlarge in sa-east-1 | $1,497.35 | [T1496.001](https://attack.mitre.org/techniques/T1496/001/) | GPU machines are the favourite target for crypto-mining with stolen keys. Confirm a team launched these on purpose. |
| HIGH | Data transfer out spike in us-east-1 | $833.35 | [T1530](https://attack.mitre.org/techniques/T1530/) | On 2026-09-29 data transfer out of us-east-1 cost $427.77, 145.4x the normal $2.94. Large unexpected transfers to the internet, another region or through a NAT gateway can mean stolen data. |
| HIGH | New region in use: us-west-2 | $526.68 | [T1535](https://attack.mitre.org/techniques/T1535/) | Spend started in us-west-2, which had no spend before. Services: AmazonBedrock. Attackers often hide resources in regions nobody watches. |
| HIGH | New service in use: AmazonBedrock | $526.68 | [T1496.004](https://attack.mitre.org/techniques/T1496/004/) | AmazonBedrock has never been billed before. Watch out: LLM access is resold by attackers ('LLMjacking'). |
| HIGH | Security service went silent: AWSCloudTrail | $0.00 | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | AWSCloudTrail (audit logging) was billed before but not in the last 2 days. Attackers switch off logging and detection to hide their activity. Check it is still enabled. |
| MEDIUM | Spend spike: AmazonEC2 | $1,800.16 | [T1496](https://attack.mitre.org/techniques/T1496/) | On 2026-09-28 AmazonEC2 cost $367.07, 8.8x its normal $41.58 per day. |
| MEDIUM | Spend spike: AmazonS3 | $876.65 | [T1496](https://attack.mitre.org/techniques/T1496/) | On 2026-09-29 AmazonS3 cost $433.20, 49.0x its normal $8.84 per day. |
