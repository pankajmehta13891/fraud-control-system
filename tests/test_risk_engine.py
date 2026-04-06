from app.services.rules_engine import message_rules, category_from_score

def test_high_risk_message():
    r = message_rules("SBI Bank", "SBI123", "Urgent verify OTP now and click http://bit.ly/test")
    assert r["rule_score"] >= 50
    assert category_from_score(r["rule_score"]) in ["High Risk", "Critical", "Suspicious"]
