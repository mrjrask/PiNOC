import json
import subprocess
from pathlib import Path


def run_formatter(expression):
    script = Path("pinoc/web/static/app.js").read_text()
    result = subprocess.run(
        ["node", "-e", f"{script}\nconsole.log(JSON.stringify({expression}));"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_byte_values_are_human_readable():
    assert run_formatter("[PiNOC.formatBytes(0), PiNOC.formatBytes(1536), PiNOC.humanValue('total_bytes', 8589934592)]") == [
        "0 B",
        "1.50 KiB",
        "8.00 GiB",
    ]


def test_temperatures_include_fahrenheit_and_celsius_labels():
    assert run_formatter("[PiNOC.formatTemperature(50), PiNOC.humanValue('temperature_f', 32)]") == [
        "122.0 °F / 50.0 °C",
        "32.0 °F / 0.0 °C",
    ]


def test_percentage_values_include_percent_symbol():
    assert run_formatter(
        "[PiNOC.formatPercent(72), PiNOC.humanValue('percent', 81.2), "
        "PiNOC.humanValue('percentage_used', 12.34)]"
    ) == ["72.0%", "81.2%", "12.3%"]


def test_ambiguous_totals_are_not_assumed_to_be_bytes():
    assert run_formatter("PiNOC.humanValue('total', 42)") == 42


def test_missing_byte_values_remain_unavailable():
    assert run_formatter(
        "[PiNOC.formatBytes(null), PiNOC.formatBytes(undefined), "
        "PiNOC.humanValue('memory_bytes', null)]"
    ) == ["—", "—", "—"]
