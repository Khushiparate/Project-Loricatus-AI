from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import numpy as np, time, requests, os, smtplib
from email.mime.text import MIMEText

OPENSEARCH_EVENT = "http://opensearch:9200/nids-events/_doc"
OPENSEARCH_INCIDENT = "http://opensearch:9200/nids-incidents/_doc"
ALERT_HOOK = "http://127.0.0.1:9200/alert"

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK")

EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_PASS = os.getenv("EMAIL_PASS")

model = IsolationForest(contamination=0.05)
model.fit(np.random.rand(500, 3))

flows = {}
alert_cache = {}
DEDUP_WINDOW = 60

def severity(flow):
    if flow["packet_count"] > 100:
        return "Critical"
    elif flow["packet_count"] > 50:
        return "High"
    elif flow["packet_count"] >20:
        return "Medium"
    else:
        return "Low"

def send_email(msg):
    if not EMAIL_FROM:
       return
    m = MIMEText(msg)
    m["Subject"] = "NIDS ALERT"
    m["From"] = EMAIL_FROM
    m["To"] = EMAIL_TO
    s = smtplib.SMTP("smtp.gmail.com", 587)
    s.starttls()
    s.login(EMAIL_FROM, EMAIL_PASS)
    s.send_message(m)
    s.quit()

def send_webhook(url, msg):
if url:
       requests.post(url, json={"text":msg})

def handle(pkt):
    if IP not in pkt:
        return

    proto = 6 if TCP in pkt else 17 if UDP in pkt else 0
    key = (pkt[IP].src, pkt[IP].dst, proto)


    flow = flows.get(key, {"count": 0, "bytes": 0, "start": time.time()})
    flow["count"] += 1
    flow["bytes"] += len(pkt)
    flows[key] = flow

    if flow["count"] >= 10:
        duration = time.time() - flow["start"]
        pred = model.predict([[flow["count"], flow["bytes"], duration]])[0]

        if pred == -1:
           sev = severity(flow)
           now = time.time()
           dedup_key = f"{pkt[IP].src}_{sev}"

           if dedup_key in alert_cache and now - alert_cache[dedup_key] < DEDUP_WINDOW:
               return

           alert_cache[dedup_key] = now

           event = {
               "src_ip": pkt[IP].src,
               "dst_ip": pkt[IP].dst,
               "packet_count": flow["count"],
               "byte_count": flow["bytes"],
               "severity": sev,
               "label": "attack",
               "timestamp": int(now * 1000)
            }

           requests.post(OPENSEARCH_EVENT, json=event)
           requests.post(OPENSEARCH_INCIDENT, json=event)
 msg = f"Attack detected from {pkt[IP].src} | Severity: {sev}"
           requests.post(ALERT_HOOK, json={"message":msg})
           send_email(msg)
           send_webhook(SLACK_WEBHOOK, msg)
           send_webhook(TEAMS_WEBHOOK, msg)

           flows.pop(key)

sniff(iface="eth0", prn=handle, store=False)
