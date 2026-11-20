# ZenSOC — Wazuh Slack Alert Bot

Wazuh SIEM과 Slack을 연동한 실시간 보안 알림 시스템.  
단순 전달을 넘어 **중복 압축 · 엔트로피 기반 이상 탐지 · IP별 행위 ML**을 단계적으로 구현했다.

---

## 주요 성과

| 항목 | 수치 |
|------|------|
| 알림 압축률 | 32건 → 3건 (90% 감소) |
| 수집 데이터 | 4,069줄 (정상 293 / 공격 3,776) |
| 오탐률 (행위 ML) | 65개 시간 창 중 0건 |
| 탐지 비교 시나리오 | 대량 브루트포스 / 느린 BOLA / IP 분산 |

---

## 아키텍처

```
Kali Linux (Hydra SSH 공격)
        │
        ▼
  wazuh-agent (호스트)
        │  alerts.json tail
        ▼
  wazuh-manager (Docker)
        │
        ├─ Rule Level 7+ 필터
        ├─ 중복 제거 (60초 윈도우)
        ├─ Shannon / ApEn 엔트로피 계산
        └─────────────────────────────▶ Slack Webhook
```

---

## 환경

```
Rocky Linux 9 (Docker)
├── Wazuh 4.9.0
│   ├── wazuh-manager
│   ├── wazuh-dashboard
│   └── wazuh-indexer
└── wazuh-agent (호스트)

Kali Linux (공격 VM)
```

---

## 구현 단계

### Phase 1 — Slack Webhook 연동
- `alerts.json` 실시간 감시 (`tail` 방식)
- Rule Level 7 이상 알림 Slack 전송
- `.env`로 Webhook URL 관리

### Phase 2 — 실제 공격 탐지 확인
- Kali에서 Hydra SSH 브루트포스 실행
- Wazuh 탐지 → Slack 수신 검증

### Phase 3 — 중복 알림 제거
- 중복 판단 키: `(rule_id, agent_name)`
- 60초 고정 윈도우 내 재발생은 카운트 누적
- 윈도우 만료 시 "N회 발생" 요약 1건만 전송
- **결과: 32건 → 3건으로 압축**

### Phase 4 — 엔트로피 계산
- 슬라이딩 윈도우: 최근 100개 alert
- **Shannon Entropy** — rule_id / level / srcip 분포의 다양성
- **Approximate Entropy (ApEn)** — level 수열의 규칙성
- 결과: `entropy_log.jsonl` (4,069줄)

### Phase 5 — 행위 ML 보강 (`behavioral_ml/`)
엔트로피는 전역 스트림 기준이라 느리고 조용한 공격에 취약하다.  
IP별 행위 패턴을 **IsolationForest**로 학습해 사각지대를 보완했다.

| 시나리오 | 엔트로피 | 행위 ML |
|----------|----------|---------|
| 대량 브루트포스 | ✅ | ✅ |
| 느린 BOLA | ⛔ | ✅ |
| 블렌딩 · IP 분산 | ⛔ | ⛔ (미해결) |

---

## 빠른 시작

```bash
# 1. 환경 설정
cp .env.example .env
# SLACK_WEBHOOK 값 입력

# 2. 컨테이너로 복사 및 실행
docker cp slack_alert.py single-node-wazuh.manager-1:/tmp/
docker cp .env single-node-wazuh.manager-1:/tmp/

docker exec -it single-node-wazuh.manager-1 bash
python3 /tmp/slack_alert.py

# 3. 엔트로피 로그 확인
docker cp single-node-wazuh.manager-1:/tmp/entropy_log.jsonl ./
```

---

## 파일 구조

```
wazuh-slack-alertbot/
├── slack_alert.py        # 메인 코드 (Phase 1~4)
├── analyze.py            # 엔트로피 분석
├── entropy_log.jsonl     # 수집 데이터 (4,069줄)
├── entropy_analysis.png  # 시각화 결과
├── behavioral_ml/        # Phase 5 — IsolationForest 탐지
├── ZenSOC_논문_초안_v2.md # 연구 초안
├── .env.example
├── requirements.txt
└── README.md
```

---

## 엔트로피 로그 형식

```json
{
  "timestamp": "2026-05-04T05:11:40",
  "window_size": 100,
  "trigger_rule_id": "5760",
  "trigger_agent": "localhost.localdomain",
  "phase": "normal",
  "shannon_rule_id": 2.4509,
  "shannon_level": 0.9757,
  "shannon_srcip": 1.0649,
  "apen_level": 0.5703
}
```

---

## 의존성

```bash
pip install requests python-dotenv
```
