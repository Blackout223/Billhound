"""Tests for reading exports, the allowlist file, webhook alerts and the command line."""

import gzip
import json
import shutil
from pathlib import Path

import pytest

from hound import notify
from hound.cli import main
from hound.loader import load_allowlist, load_billing_csv

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "compromised_month.csv"


def test_reads_gzipped_csv(tmp_path):
    gz_path = tmp_path / "export.csv.gz"
    with open(SAMPLE, "rb") as plain, gzip.open(gz_path, "wb") as packed:
        shutil.copyfileobj(plain, packed)
    assert load_billing_csv(gz_path) == load_billing_csv(SAMPLE)


def test_reads_parquet(tmp_path):
    pa_csv = pytest.importorskip("pyarrow.csv")
    pq = pytest.importorskip("pyarrow.parquet")
    parquet_path = tmp_path / "export.parquet"
    pq.write_table(pa_csv.read_csv(SAMPLE), parquet_path)
    rows = load_billing_csv(parquet_path)
    assert len(rows) == 248
    assert rows[0]["account"] == "111122223333"


def test_missing_account_column_is_allowed(tmp_path):
    lines = SAMPLE.read_text().splitlines()
    header = lines[0].split(",")
    keep = [i for i, name in enumerate(header) if name != "line_item_usage_account_id"]
    trimmed = "\n".join(",".join(line.split(",")[i] for i in keep) for line in lines)
    path = tmp_path / "single_account.csv"
    path.write_text(trimmed + "\n")
    assert load_billing_csv(path)[0]["account"] == "unknown"


def test_allowlist_rejects_unknown_keys(tmp_path):
    path = tmp_path / "allow.json"
    path.write_text(json.dumps({"region": ["eu-west-2"]}))  # typo: should be "regions"
    with pytest.raises(ValueError):
        load_allowlist(path)


def test_cli_allowlist_removes_findings(tmp_path):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"regions": ["sa-east-1", "us-west-2"]}))
    report = tmp_path / "report.json"
    main([str(SAMPLE), "--allowlist", str(allow), "--json", str(report)])
    rules = [f["rule"] for f in json.loads(report.read_text())["findings"]]
    assert "NEW_REGION" not in rules
    assert "GPU_INSTANCE" in rules  # the allowlist only silences what it names


def test_cli_exit_codes(tmp_path):
    normal = SAMPLE.parent / "normal_month.csv"
    assert main([str(normal)]) == 0
    assert main([str(SAMPLE)]) == 1
    assert main([str(tmp_path / "missing.csv")]) == 2


def test_webhook_posts_summary(monkeypatch):
    sent = {}

    class FakeResponse:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout):
        sent["url"] = request.full_url
        sent["body"] = json.loads(request.data)
        return FakeResponse()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    findings = [{"severity": "HIGH", "title": "New region in use: sa-east-1",
                 "cost": 1497.35, "mitre": "T1535"}]
    assert notify.send_webhook("https://hooks.example.com/abc", findings, "bill.csv")
    assert sent["url"] == "https://hooks.example.com/abc"
    assert "1 high severity" in sent["body"]["text"]


def test_webhook_refuses_plain_http():
    assert not notify.send_webhook("http://hooks.example.com/abc", [], "bill.csv")
