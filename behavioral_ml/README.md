# behavioral_ml — 엔트로피(ZenSOC)에 행위 ML 을 더해 사각지대를 메움

ZenSOC(이 레포)는 Wazuh 경보 스트림의 **엔트로피**로 공격을 탐지한다. 실측해 보니 엔트로피는
**대량·반복 공격(브루트포스)** — 한 소스가 스트림을 뒤덮어 다양성이 급락하는 — 에 강하지만,
**느리고 조용한 공격**은 못 본다. 이 디렉터리는 그 사각지대를 **행위 ML(IP별 이상 탐지)** 로 메우고,
둘을 같은 트래픽에서 머리맞대 비교한 자료다.

## 왜 필요한가 — 엔트로피 한 가지의 한계

| | 엔트로피(ZenSOC, 전역 스트림) | 행위 ML(IP별 15분 창) |
|---|---|---|
| 잘 잡음 | 대량·반복(브루트포스) → 다양성 붕괴 | 느린 열거·은밀 공격 |
| 못 잡음 | 느린/소수 공격 → 전역 평균이 안 흔들림 | IP 분산 → 창당 요청 부족 |
| 집계 단위 | **전역**(모든 IP 합산) | **소스(IP)별** |

전역 엔트로피는 "집단의 다양성"이라 조용한 한 IP 를 **원리적으로** 분리하지 못한다(윈도우를 키워도 안 됨 — `window_sweep.py`). 소스별로 봐야 잡힌다 = ML 의 역할.

## 머리맞댄 결과 (`compare.py`, 같은 합성 트래픽)

| 시나리오 | 엔트로피(전역) | 행위 ML(IP별) |
|---|---|---|
| 정상 | ✅ 조용 | ✅ 조용 |
| 대량 브루트포스 | ✅ 탐지 (경로 다양성 41σ 급락) | ✅ 탐지 |
| 느린 BOLA | ⛔ 놓침 (2σ) | ✅ 탐지 (−0.12) |
| 브라우저 블렌딩 | ⛔ 놓침 | ⛔ 놓침 |
| IP 분산 | ⛔ 놓침 | ⛔ 놓침 (창당 5건 미만) |

→ **사각지대가 반대.** 브루트포스는 엔트로피가, 느린 공격은 ML 이 잡는다. 둘을 **OR 로 합치면** 단독보다 넓게 덮인다. 블렌딩·IP 분산은 둘 다 숙제(계정·세션 단위가 다음 단계). 그림 `compare.png`.

## 행위 ML 은 어디서 왔나 — 실제 트래픽·다양한 공격으로 검증됨

`ml/` 의 모델은 **다른 프로젝트(zeldaim/shadow_api_monitoring, e2e_story)** 에서 가져온 **고정 모델**이다. ZenSOC 의 "실습 1회 4069줄"과 달리:
- **실제 트래픽 학습**: 팀 웹 접근 로그 106만 줄에서 뽑은 IP×15분 창 199개(스캐너·규칙적중 창 제외)로 IsolationForest 학습.
- **공격 다양화 평가**: 회피 변종 7종으로 탐지율 측정(순차·느림 100%, 다API 55%, 블렌딩 25%, IP분산 0%), 학습 외 로그 오탐 0.55%.
- 원본·상세: `../../shadow_api_monitoring/e2e_story/` (ml·eval), 근거 `docs/참고문헌_기술근거.md`.

> ZenSOC 는 SSH/호스트 경보, 이 ML 은 HTTP API 트래픽이라 **특징은 도메인별로 다르다.** 옮겨지는 것은 **방법(소스별 이상탐지)·평가틀·"엔트로피+ML 복합" 설계**다. Wazuh 경보 스트림용 ML 은 `../../wazuh-ml/wazuh_ml.py`(IsolationForest, 에이전트별 10분 창)를 같은 방식으로 붙일 수 있다.

## 파일 · 실행

```
behavioral_ml/
├─ entropy_detect.py   ZenSOC 수식(Shannon/ApEn) + 전역 윈도우 지속-하락 탐지
├─ compare.py          같은 트래픽에 엔트로피 vs ML → results.md · compare.png
├─ window_sweep.py     윈도우를 키워도 느린 공격은 못 잡음(집계 단위 문제) 증명
├─ variants_base.py    공격 변종 생성(e2e 에서)
├─ ml/                 e2e 고정 ML (features·detect·model, HTTP 트래픽용)
├─ results.md          비교 결과(+윈도우 스윕 부록)
└─ compare.png         시나리오별 탐지 그림
```

```bash
pip install -r ../requirements.txt scikit-learn joblib numpy pyyaml matplotlib
python behavioral_ml/compare.py        # 비교표·그림
python behavioral_ml/window_sweep.py   # 윈도우 스윕
```

## 한계 (정직하게)

- 합성 트래픽(상태코드·분포 단순)·오프라인 재생 — Wazuh/EDA 실시간 부하·실데이터 분포는 미측정.
- ML 특징은 HTTP 전용 — ZenSOC 의 SSH 경보 도메인에 그대로 쓰려면 경보-기반 특징으로 재학습 필요.
- 블렌딩·IP 분산은 두 방법 다 약함 → 계정·세션 단위 탐지가 다음 과제.
