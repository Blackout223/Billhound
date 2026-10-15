"""Turns findings into a readable report for the terminal or a Markdown file."""

ICONS = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[  ]"}


def print_report(findings, file_name):
    print(f"\nCostCanary report for {file_name}")
    print("=" * 60)
    if not findings:
        print("No suspicious spending patterns found.")
        return
    for finding in findings:
        print(f"\n{ICONS[finding['severity']]} {finding['severity']}: {finding['title']}")
        print(f"     Cost in recent period: ${finding['cost']:,.2f}")
        print(f"     {finding['detail']}")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    print(f"\n{len(findings)} finding(s), {high} high severity.")


def write_markdown(findings, file_name, output_path):
    lines = [f"# CostCanary report: `{file_name}`", ""]
    if not findings:
        lines.append("No suspicious spending patterns found.")
    else:
        lines += ["| Severity | Finding | Recent cost | Details |",
                  "|---|---|---:|---|"]
        for f in findings:
            lines.append(f"| {f['severity']} | {f['title']} | ${f['cost']:,.2f} | {f['detail']} |")
    with open(output_path, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
    print(f"Markdown report saved to {output_path}")
