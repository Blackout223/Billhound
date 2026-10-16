# CostCanary report: `sample_data/compromised_month.csv`

| Severity | Finding | Recent cost | Details |
|---|---|---:|---|
| HIGH | New region in use: sa-east-1 | $1,497.35 | Spend started in sa-east-1, which had no spend before. Services: AmazonEC2. Attackers often hide resources in regions nobody watches. |
| HIGH | New GPU instances: p3.8xlarge in sa-east-1 | $1,497.35 | GPU machines are the favourite target for crypto-mining with stolen keys. Confirm a team launched these on purpose. |
| HIGH | Data transfer out spike in us-east-1 | $833.35 | On 2026-09-29 data leaving AWS from us-east-1 cost $427.77, 145.4x the normal $2.94. Large unexpected downloads can mean stolen data. |
| HIGH | New region in use: us-west-2 | $526.68 | Spend started in us-west-2, which had no spend before. Services: AmazonBedrock. Attackers often hide resources in regions nobody watches. |
| HIGH | New service in use: AmazonBedrock | $526.68 | AmazonBedrock has never been billed before. Watch out: LLM access is resold by attackers ('LLMjacking'). |
| HIGH | Security service went silent: AWSCloudTrail | $0.00 | AWSCloudTrail (audit logging) was billed before but not in the last 2 days. Attackers switch off logging and detection to hide their activity. Check it is still enabled. |
| MEDIUM | Spend spike: AmazonEC2 | $1,800.16 | On 2026-09-28 AmazonEC2 cost $367.07, 8.8x its normal $41.58 per day. |
| MEDIUM | Spend spike: AmazonS3 | $876.65 | On 2026-09-29 AmazonS3 cost $433.20, 49.0x its normal $8.84 per day. |
