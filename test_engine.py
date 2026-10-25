import pytest
from engine import analyze
from samples import SAMPLES, as_text

SCAMS = [
    "Fake bank officer (English)",
    "Fake bank officer (Hinglish)",
    "Fake job offer",
    "Fake police / arrest threat",
]


@pytest.mark.parametrize("name", SCAMS)
def test_scams_are_high(name):
    r = analyze(as_text(name))
    assert r["level"] == "High", (name, r["score"], [s["key"] for s in r["signals"]])


def test_normal_chat_is_low():
    r = analyze(as_text("Normal chat with a friend"))
    assert r["level"] == "Low"
    assert r["score"] < 20


def test_real_bank_alert_is_not_high():
    r = analyze(as_text("Real bank alert (safe)"))
    assert r["level"] != "High"


def test_escalation_detected():
    r = analyze(as_text("Fake bank officer (English)"))
    assert r["escalation"] is True


def test_empty_input():
    assert "error" in analyze("   \n ")


def test_whatsapp_format_parsed():
    r = analyze("12/10/25, 9:14 pm - Unknown: share otp now, account will be blocked")
    assert r["messages"][0]["sender"] == "Unknown"
    assert r["level"] in ("Medium", "High")
