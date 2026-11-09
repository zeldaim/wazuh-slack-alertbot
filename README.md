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
- 첫 발생 시점부터 60초 고정 윈도우 내 재발생 시 카운트만 증가
- 윈도우 만료 시 "N회 발생" 요약 알림 1건 전송
- 상태 저장: 메모리 기반 dict

**결과:** 실험 중 32건 → 3건으로 압축되는 것을 관찰 (원자료는 보존하지 않음)

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

> **2026-11-10 정정** — 논문은 [`ZenSOC_논문_초안_v2.md`](ZenSOC_논문_초안_v2.md) (v1 은 기록으로 유지).

실제 데이터(`entropy_log.jsonl`)에서는 예상과 **반대 방향**이었다:

```
정상 구간(293건, 룰 3개 순환)  →  level·srcip 엔트로피 0, ApEn 0 (상수)
공격 구간(Hydra 1회)          →  평균 level 0.93 · srcip 0.98 · ApEn 0.47 (상승)
```

- 방향은 무엇을 집계하느냐에 달려 있다: 정상 경보가 소수 룰의 반복이면, 공격이 새 룰·레벨·IP 를 끌어와 엔트로피가 **오른다**.
- 정상 구간이 상수라 어떤 지표든 두 구간이 갈리는 것은 당연하다 → **탐지 성능의 증거가 아니라 단일 사례의 관찰**.
- srcip 1.0 은 IP 없는 경보("Unknown")와 공격 IP 가 반반 섞인 값일 가능성이 높다(미확인).

---

## 한계와 보강 — 엔트로피 + 행위 ML ([behavioral_ml/](behavioral_ml/README.md))

엔트로피는 **전역 스트림**의 다양성을 본다 → 브루트포스처럼 뒤덮는 공격엔 강하지만 **느리고 조용한 공격은 정상에 묻혀 못 본다**(윈도우를 키워도 안 됨 — 집계 단위 문제, `behavioral_ml/window_sweep.py`). 이를 **IP별 행위 ML(IsolationForest)** 로 보강하고 같은 트래픽에서 비교했다.

| 시나리오 | 엔트로피(전역) | 행위 ML(IP별) |
|---|---|---|
| 대량 브루트포스 | ✅ (41σ 급락) | ✅ |
| 느린 BOLA | ⛔ | ✅ (−0.12) |
| 블렌딩 · IP 분산 | ⛔ | ⛔ (다음 과제) |

→ 사각지대가 반대 방향이라는 **예비 관찰**이다 (합성 HTTP 트래픽, 시나리오당 1회 실행, ML 의 정상 시나리오는 측정 안 함, OR 결합은 미측정). ML 은 실 서비스 로그 106만 줄로 학습했고, 오탐은 ~~0.55%~~(평가 데이터가 학습과 겹쳐 무효) → 시간 분할 재측정 65창 중 0건(95% 상한 약 5%)(출처: [zeldaim/shadow_api_monitoring](https://github.com/zeldaim/shadow_api_monitoring) e2e_story). 상세·실행·그림: [`behavioral_ml/`](behavioral_ml/). 기술 근거 문헌: shadow_api_monitoring `docs/참고문헌_기술근거.md`.
