import json
import urllib.request

from  config import DISCORD_WEBHOOK_URL, DISCORD_THREAT_ALERTS_ENABLED


def send_discord_alert(message: str):
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        data = json.dumps({"content": message, "username": "NPM Security"}).encode()
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"⚠️ Discord webhook error: {e}")


def send_threat_discord_alert(event: dict, action: str = "detected"):
    if not DISCORD_WEBHOOK_URL or not DISCORD_THREAT_ALERTS_ENABLED:
        return
    score = int(event.get("threat_score") or 0)
    reasons = ", ".join(event.get("threat_reasons") or []) or "—"
    msg = "\n".join([
        "🚨 **NPM Security Threat**",
        f"Action: **{action.upper()}**",
        f"IP: `{event.get('ip', '—')}`",
        f"Pays: `{event.get('country_code', '—')}` · `{event.get('country_name', '—')}`",
        f"ISP: `{event.get('isp', '—')}`",
        f"Score: **{score}/100**",
        f"Type: `{event.get('threat', 'normal')}`",
        f"Raisons: `{reasons}`",
        f"Host: `{event.get('host', '—')}`",
        f"URI: `{str(event.get('uri', '—'))[:250]}`",
    ])
    send_discord_alert(msg)
