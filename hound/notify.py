"""Sends a short summary of the findings to a chat webhook, such as a Slack incoming webhook."""

import json
import urllib.error
import urllib.request

MAX_LISTED = 10  # keep the chat message short; the full report is in the files


def build_message(findings, file_name):
    """Plain-text summary: counts first, then the most important findings."""
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    lines = [f"BillHound: {len(findings)} finding(s), {high} high severity, in {file_name}"]
    for f in findings[:MAX_LISTED]:
        lines.append(f"- {f['severity']} {f['title']} (${f['cost']:,.2f}, MITRE {f['mitre']})")
    if len(findings) > MAX_LISTED:
        lines.append(f"...and {len(findings) - MAX_LISTED} more.")
    return "\n".join(lines)


def send_webhook(url, findings, file_name, timeout=10):
    """POST {"text": ...} to the webhook. Returns True if it was accepted.

    A failed send only prints a warning, so a chat outage never hides the scan result.
    """
    if not url.startswith("https://"):
        # Webhook URLs are secrets. Never send them, or the findings, over plain HTTP.
        print("Warning: webhook not sent, the URL must start with https://")
        return False
    body = json.dumps({"text": build_message(findings, file_name)}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            ok = 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Warning: webhook not sent: {error}")
        return False
    print("Webhook alert sent." if ok else f"Warning: webhook returned status {response.status}")
    return ok
