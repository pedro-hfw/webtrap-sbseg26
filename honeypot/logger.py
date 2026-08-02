import threading, json
from flask import request
from datetime import datetime
from pathlib import Path

BASE_DIR     = Path(__file__).resolve().parent
LOG_FILE     = str(BASE_DIR / "logs" / "requests.ndjson")
TRACKER_FILE = str(BASE_DIR / "logs" / "tracker.ndjson")

_tracker_lock  = threading.Lock()
threat_tracker = {}

# Ajustável para preferência
THREAT_MEDIUM = 3
THREAT_HIGH   = 7


def ip_tracker(ip: str, attack_type: str) -> None:

    with _tracker_lock:

        if ip not in threat_tracker:
            threat_tracker[ip] = {"count": 0, "sqli": 0, "xss": 0,
                                  "rce": 0, "lfi": 0, "timestamp": ""}
        
        entry = threat_tracker[ip]

        entry["count"] += 1
        
        if attack_type in entry:
            entry[attack_type] += 1
        
        entry["timestamp"] = str(datetime.now())

        log_tracker(ip, entry)


def threat_level(ip: str) -> str:

    count = threat_tracker.get(ip, {}).get("count", 0)
    
    if count >= THREAT_HIGH:   return "high"
    if count >= THREAT_MEDIUM: return "medium"
    
    return "low"

# --------------------
# Logando Requisições
# --------------------


def log_request(prediction: str, attack_type: str, decision: str) -> None:
    
    ip = request.remote_addr
    
    data = {
        "timestamp":    str(datetime.now()),
        "src_ip":       ip,
        "src_port":     request.environ.get("REMOTE_PORT"),
        "dst_port":     request.environ.get("SERVER_PORT"),
        "method":       request.method,
        "path":         request.path,
        "query":        request.query_string.decode(),
        "headers":      dict(request.headers),
        "body":         request.get_data(as_text=True),
        "threat_level": threat_level(ip),
        "prediction":   prediction,
        "attack_type":  attack_type,
        "decision":     decision,
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")


# ----------------
# Logando Tracker
# ----------------


def log_tracker(ip: str, entry):

    with open(TRACKER_FILE, "a") as f:
        f.write(json.dumps({"ip": ip, **entry}) + "\n")