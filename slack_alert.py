import time
import json
import math
import requests
import os
from collections import deque, Counter
from dotenv import load_dotenv

load_dotenv()
WEBHOOK = os.environ.get("SLACK_WEBHOOK")

# ── 설정 ─────────────────────────────────────────
DEDUP_WINDOW   = 60
MIN_LEVEL      = 0        # 모든 alert 수집 (정상 트래픽 포함)
WINDOW_SIZE    = 100
ENTROPY_LOG    = "/tmp/entropy_log.jsonl"

# ── 상태 저장 ────────────────────────────────────
dedup_state  = {}
alert_window = deque(maxlen=WINDOW_SIZE)


# ── Shannon Entropy ──────────────────────────────
def shannon_entropy(values):
    if not values:
        return 0.0
    counts = Counter(values)
    total  = len(values)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )


# ── Approximate Entropy (ApEn) ───────────────────
def approximate_entropy(values, m=2, r_ratio=0.2):
    N = len(values)
    if N < m + 2:
        return 0.0
    mean = sum(values) / N
    std  = (sum((v - mean) ** 2 for v in values) / N) ** 0.5
    r    = r_ratio * std if std > 0 else 1e-6

    def phi(m_len):
        templates = [values[i:i + m_len] for i in range(N - m_len + 1)]
        counts = []
        for t in templates:
            cnt = sum(
                1 for s in templates
                if max(abs(t[k] - s[k]) for k in range(m_len)) <= r
            )
            counts.append(cnt / (N - m_len + 1))
        return sum(math.log(c) for c in counts if c > 0) / (N - m_len + 1)

    return abs(phi(m) - phi(m + 1))


# ── 엔트로피 계산 및 로그 저장 ───────────────────
def compute_and_log_entropy(alert):
    rule_id = str(alert.get("rule", {}).get("id", "0"))
    level   = alert.get("rule", {}).get("level", 0)
    agent   = alert.get("agent", {}).get("name", "Unknown")
    srcip   = alert.get("data", {}).get("srcip", "Unknown")

    alert_window.append({
        "rule_id": rule_id,
        "level":   level,
        "agent":   agent,
        "srcip":   srcip,
    })

    if len(alert_window) < 10:
        return

    rule_ids = [a["rule_id"] for a in alert_window]
    levels   = [a["level"]   for a in alert_window]
    srcips   = [a["srcip"]   for a in alert_window]

    entropy_data = {
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
        "window_size":      len(alert_window),
        "trigger_rule_id":  rule_id,
        "trigger_agent":    agent,
        "phase":            "normal",   # 나중에 attack으로 수동 구분 가능
        "shannon_rule_id":  round(shannon_entropy(rule_ids), 4),
        "shannon_level":    round(shannon_entropy([str(l) for l in levels]), 4),
        "shannon_srcip":    round(shannon_entropy(srcips), 4),
        "apen_level":       round(approximate_entropy(levels), 4),
    }

    with open(ENTROPY_LOG, "a") as f:
        f.write(json.dumps(entropy_data) + "\n")


# ── 중복 제거 ─────────────────────────────────────
def flush_expired_windows():
    now     = time.time()
    expired = [k for k, v in dedup_state.items()
               if now - v["first_seen"] >= DEDUP_WINDOW]
    for key in expired:
        state = dedup_state.pop(key)
        if state["count"] > 1:
            send_summary(key, state)


def send_summary(key, state):
    rule_id, agent = key
    level  = state["level"]
    desc   = state["desc"]
    count  = state["count"]
    mitre  = state["mitre"]

    emoji   = ":red_circle:" if level >= 11 else ":large_yellow_circle:"
    message = (
        f"{emoji} *Wazuh Alert (요약)*\n"
        f"*Level:* {level}\n"
        f"*Rule:* {desc}  (`{rule_id}`)\n"
        f"*Agent:* {agent}\n"
        f"*60초 내 발생 횟수:* {count}회"
    )
    if mitre:
        message += f"\n*MITRE:* {', '.join(mitre)}"
    requests.post(WEBHOOK, json={"text": message})


# ── 메인 알림 처리 ────────────────────────────────
def send_alert(alert):
    level   = alert.get("rule", {}).get("level", 0)
    desc    = alert.get("rule", {}).get("description", "Unknown")
    rule_id = str(alert.get("rule", {}).get("id", "0"))
    agent   = alert.get("agent", {}).get("name", "Unknown")
    mitre   = alert.get("rule", {}).get("mitre", {}).get("technique", [])

    # 엔트로피는 모든 alert 수집
    compute_and_log_entropy(alert)

    if level < 7:   # Slack 알림은 레벨 7 이상만
        return

    flush_expired_windows()

    key = (rule_id, agent)
    now = time.time()

    if key in dedup_state:
        dedup_state[key]["count"] += 1
        return

    dedup_state[key] = {
        "first_seen": now,
        "count": 1,
        "level": level,
        "desc":  desc,
        "mitre": mitre,
    }

    emoji   = ":red_circle:" if level >= 11 else ":large_yellow_circle:"
    message = (
        f"{emoji} *Wazuh Alert*\n"
        f"*Level:* {level}\n"
        f"*Rule:* {desc}  (`{rule_id}`)\n"
        f"*Agent:* {agent}"
    )
    if mitre:
        message += f"\n*MITRE:* {', '.join(mitre)}"
    requests.post(WEBHOOK, json={"text": message})


# ── 파일 감시 ─────────────────────────────────────
def watch_alerts(filepath):
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                flush_expired_windows()
                time.sleep(1)
                continue
            try:
                alert = json.loads(line)
                send_alert(alert)
            except Exception:
                pass


if __name__ == "__main__":
    watch_alerts("/var/ossec/logs/alerts/alerts.json")
