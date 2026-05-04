# ZenSOC — Wazuh Slack Alert Bot

Wazuh SIEM과 Slack을 연동한 실시간 보안 알림 시스템.  
Shannon Entropy와 Approximate Entropy를 활용해 SSH 브루트포스 등 공격 패턴을 탐지한다.

---

## 환경

```
Rocky Linux 9 (Docker)
├── Wazuh 4.9.0
│   ├── wazuh-manager
│   ├── wazuh-dashboard
│   └── wazuh-indexer
└── wazuh-agent (호스트)

Kali Linux (공격 VM) — 192.168.190.128
```

---

## 구현 단계

### Phase 1 — Slack Webhook 연동
- Wazuh `alerts.json` 실시간 감시 (`tail` 방식)
- Rule Level 7 이상 alert Slack 전송
- `.env` 파일로 Webhook URL 관리

### Phase 2 — 실제 공격 탐지 확인
- Kali Linux에서 Hydra SSH 브루트포스 공격
- Wazuh 탐지 → Slack 알림 정상 수신 확인

### Phase 3 — 중복 알림 제거
- 중복 판단 키: `(rule_id, agent_name)`
- 60초 슬라이딩 윈도우 내 재발생 시 카운트만 증가
- 윈도우 만료 시 "N회 발생" 요약 알림 1건 전송
- 상태 저장: 메모리 기반 dict

**결과:** 32건 → 3건으로 압축

### Phase 4 — 엔트로피 계산
- 슬라이딩 윈도우 크기: 최근 100개 alert 기준
- **Shannon Entropy:** rule_id / level / srcip 분포의 다양성 측정
- **Approximate Entropy (ApEn):** level 수열의 규칙성 측정
- 결과 저장: `entropy_log.jsonl` (JSONL 형식)

**데이터 수집 결과**

| 구간 | 줄 수 |
|------|-------|
| 정상 트래픽 | 0 ~ 293 |
| 공격 (Hydra) | 293 ~ 4069 |
| 총계 | 4069줄 |

---

## 실행 방법

### 1. 환경 설정

```bash
# .env 파일 생성
cp .env.example .env
# SLACK_WEBHOOK 값 입력
```

### 2. 컨테이너로 복사 및 실행

```bash
docker cp slack_alert.py single-node-wazuh.manager-1:/tmp/
docker cp .env single-node-wazuh.manager-1:/tmp/

docker exec -it single-node-wazuh.manager-1 bash
python3 /tmp/slack_alert.py
```

### 3. 엔트로피 로그 확인

```bash
# 컨테이너 안에서
tail -f /tmp/entropy_log.jsonl

# 호스트로 꺼내기
docker cp single-node-wazuh.manager-1:/tmp/entropy_log.jsonl ./
```

---

## 파일 구조

```
wazuh-slack-alertbot/
├── slack_alert.py        # 메인 코드 (Phase 1~4 누적)
├── entropy_log.jsonl     # 논문용 엔트로피 데이터
├── .env.example          # Webhook URL 예시
├── requirements.txt      # 필요 패키지
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

## 필요 패키지

```
requests
python-dotenv
```

```bash
pip install requests python-dotenv
```

---

## 논문 활용 방향

정상 구간과 공격 구간의 엔트로피 값을 비교해 공격 탐지 가능성을 증명한다.

```
정상 트래픽  →  Shannon 높음 + ApEn 높음
공격 진행 중 →  Shannon 낮음 + ApEn 낮음
```

> "룰 기반 탐지의 한계를 엔트로피로 보완한다"
