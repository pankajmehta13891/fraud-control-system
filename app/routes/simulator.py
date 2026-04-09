import requests
import time
import random

# --- SETTINGS ---
# Switch this to your Render URL when deploying
RENDER_URL = "http://127.0.0.1:5000" 
# RENDER_URL = "http://127.0.0.1:5000" # For local testing

LOGIN_DATA = {
    "username": "banker", 
    "password": "banker123" 
}

# Templates from your training logic to trigger Regex and ML
SCAM_TEMPLATES = [
    "Urgent: your account will be blocked. Verify OTP now and click http://bit.ly/verify to avoid suspension.",
    "KYC update required immediately. Share OTP, PIN and CVV to continue service.",
    "You won a lottery prize. Confirm bank details and pay a small processing fee.",
    "Refund ready. Call customer care now and tell OTP to receive cashback.",
    "Your UPI payment failed. Login and verify password now at www.bank-verify.click."
]

SAFE_TEMPLATES = [
    "Your salary has been credited to account ending {}.",
    "Reminder: your card bill is due on 10th of this month.",
    "Transaction alert: INR {:,} paid at merchant store.",
    "Security alert: login from a new device was blocked by app settings.",
    "Thank you for using our services."
]

def run_secure_simulation():
    session = requests.Session()
    
    print(f"🔐 Logging into {RENDER_URL}...")
    try:
        login_resp = session.post(f"{RENDER_URL}/login", data=LOGIN_DATA)
        if login_resp.status_code != 200 or "Login" in login_resp.text:
            print("❌ Login Failed! Check credentials or if Render is 'awake'.")
            return
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return

    print("✅ Login Successful! Starting 500-record data stream...")

    for i in range(1, 501):
        is_fraud = random.random() < 0.4
        cust_id = random.randint(1, 4) 

        # --- FIX: Generate Message Body ---
        if is_fraud:
            body = random.choice(SCAM_TEMPLATES)
            # Inject a random reference to make every message unique
            body += f" [Ref: {random.randint(1000, 9999)}]"
        else:
            body = random.choice(SAFE_TEMPLATES).format(
                random.randint(1000, 9999), 
                random.randint(500, 5000)
            )

        msg_payload = {
            "customer_id": cust_id,
            "sender_name": "Fraud_Bot" if is_fraud else "Official_Bank",
            "sender_id": f"SND-{random.randint(100, 999)}",
            "phone_or_email": f"+91{random.randint(7000000000, 9999999999)}",
            "channel": random.choice(["SMS", "WhatsApp", "Email"]),
            "body": body
        }

        # --- Generate Transaction Payload ---
        txn_payload = {
            "customer_id": cust_id,
            "txn_ref": f"TXN-{random.randint(100000, 999999)}",
            "txn_type": random.choice(["UPI", "NEFT", "IMPS"]),
            "amount": float(random.randint(40000, 250000)) if is_fraud else float(random.randint(100, 8000)),
            "beneficiary": f"Recipient_{random.randint(100, 999)}",
            "beneficiary_risk": random.randint(75, 100) if is_fraud else random.randint(0, 25),
            "hour_of_day": random.randint(0, 23),
            "geo_mismatch": 1 if is_fraud else 0,
            "scam_message_minutes": random.randint(1, 45) if is_fraud else 9999,
            "repeated_small_txn": random.randint(0, 1),
            "international_flag": 1 if is_fraud else 0,
            "cash_withdrawal": random.randint(0, 1) if is_fraud else 0
        }

        try:
            session.post(f"{RENDER_URL}/api/predict/message", json=msg_payload)
            session.post(f"{RENDER_URL}/api/predict/transaction", json=txn_payload)
            
            if i % 25 == 0:
                print(f"📈 {i}/500 records synced...")
        except Exception as e:
            print(f"⚠️ Error at record {i}: {e}")
            break

        # Slow down for Render's free tier stability
        time.sleep(0.2) 

if __name__ == "__main__":
    run_secure_simulation()