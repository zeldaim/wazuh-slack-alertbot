#!/usr/bin/env python3
"""머리맞댄 비교 — 같은 트래픽에 ① ZenSOC 엔트로피(전역) ② 행위 ML(IP별, e2e 고정모델) 을 둘 다 돌린다.

  python compare.py        → results.md · compare.png (같은 폴더)

시나리오마다 '정상 배경 트래픽(여러 IP) + 공격'을 한 전역 스트림으로 만들고:
- 엔트로피: 전역 윈도우 다양성이 baseline 대비 급락하면 탐지 (브루트포스처럼 뒤덮는 공격에 강함)
- ML: 공격 IP 의 15분 창 특징이 고정모델 임계값 아래면 탐지 (조용한·열거 공격에 강함)
결론: 둘의 사각지대가 반대 → 합쳐야 덮인다.
"""
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "ml"))
sys.path.insert(0, HERE)
from entropy_detect import EntropyDetector            # noqa: E402
import features as F                                    # noqa: E402
import detect as D                                      # noqa: E402

NORMAL_PATHS = ["/", "/products.php", "/api/v2/products", "/api/v2/products/{r}", "/api/v2/cart",
                "/assets/style.css", "/assets/app.js", "/api/v2/users/me", "/api/v2/orders/me",
                "/api/v2/categories", "/login.php", "/api/v2/products/search"]


def bg_normal(rng, t0, minutes, n_ips=12, rate_per_min=8):
    """여러 IP 의 정상 브라우징 — 전역 스트림의 배경."""
    reqs = []
    ips = [f"10.1.{rng.randint(0,255)}.{rng.randint(2,254)}" for _ in range(n_ips)]
    t = t0
    for _ in range(int(minutes * rate_per_min)):
        t += timedelta(seconds=rng.expovariate(rate_per_min / 60))
        ip = rng.choice(ips)
        p = rng.choice(NORMAL_PATHS).replace("{r}", str(rng.randint(1, 50)))
        st = 200 if rng.random() < 0.9 else rng.choice([200, 404, 302])
        reqs.append((ip, p, st, t))
    return reqs


def atk_flood(rng, t0):          # 브루트포스/대량 — 한 IP 가 스트림을 뒤덮음
    ip = f"10.9.{rng.randint(0,255)}.{rng.randint(2,254)}"; reqs = []; t = t0
    for i in range(300):
        t += timedelta(seconds=rng.uniform(0.1, 0.5))
        reqs.append((ip, "/api/v2/login", rng.choice([401, 401, 401, 200]), t))
    return reqs, {ip}


def atk_slow(rng, t0):           # 느린 BOLA (명세 안 열거, 14~26초)
    ip = f"10.9.{rng.randint(0,255)}.{rng.randint(2,254)}"; reqs = []; t = t0
    for i in range(25):
        t += timedelta(seconds=rng.uniform(14, 26))
        reqs.append((ip, f"/api/v2/orders/{1000+i}", 200, t))
    return reqs, {ip}


def atk_blend(rng, t0):          # 브라우저 UA + 정상에 섞은 공격
    ip = f"10.9.{rng.randint(0,255)}.{rng.randint(2,254)}"; reqs = []; t = t0
    for i in range(40):
        t += timedelta(seconds=rng.uniform(8, 20))
        if rng.random() < 0.4:
            reqs.append((ip, f"/api/v2/orders/{1000+i}", 200, t))
        else:
            reqs.append((ip, rng.choice(NORMAL_PATHS).replace("{r}", str(rng.randint(1,50))), 200, t))
    return reqs, {ip}


def atk_distributed(rng, t0):    # 여러 IP 로 분산 (창당 몇 건)
    reqs = []; t = t0; ips = set()
    for i in range(25):
        ip = f"10.9.{rng.randint(0,255)}.{rng.randint(2,254)}"; ips.add(ip)
        t += timedelta(seconds=rng.uniform(14, 26))
        reqs.append((ip, f"/api/v2/orders/{1000+i}", 200, t))
    return reqs, ips


SCEN = {"정상(오탐확인)": None, "대량 브루트포스": atk_flood, "느린 BOLA": atk_slow,
        "브라우저 블렌딩": atk_blend, "IP 분산": atk_distributed}


def to_log_lines(reqs):
    """(ip,path,status,t) → Apache combined 줄 (features.parse 가 읽게)."""
    ua = "Mozilla/5.0"
    return [f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET {p} HTTP/1.1" {st} 312 "-" "{ua}"'
            for ip, p, st, t in sorted(reqs, key=lambda r: r[3])]


def ml_detect(scorer, reqs, attacker_ips, tmp):
    open(tmp, "w", encoding="utf-8").write("\n".join(to_log_lines(reqs)) + "\n")
    rows = F.parse(tmp)
    by = {}
    for r in rows:
        by.setdefault(r[0], []).append(r)
    hi = scorer.meta["threshold_high"]
    best = None
    for ip in attacker_ips:
        rs = by.get(ip, [])
        if len(rs) < 5:
            continue
        s = scorer.score(F.featurize(rs))[0]   # detect.Scorer.score → (점수, 심각도, 이유)
        best = s if best is None else min(best, s)
    if best is None:
        return {"caught": False, "score": None, "note": "공격 IP 가 창당 5건 미만 — 판단 불가"}
    return {"caught": best < hi, "score": round(best, 4), "note": ""}


def main():
    rng = random.Random(7)
    t0 = datetime(2026, 11, 10, 0, 0, 0, tzinfo=timezone.utc)
    BG = dict(minutes=30, n_ips=12, rate_per_min=8)   # baseline·테스트 배경 동일 조건 (공정)
    ed = EntropyDetector(window=100, k=4.0)
    # baseline = 공격 없는 정상 배경 여러 번(시드 다르게) 이어붙여 평균·표준편차 안정화
    import statistics
    base_series = []
    for seed in range(6):
        base_series += ed._series([(ip, p, st, t) for ip, p, st, t in bg_normal(random.Random(100 + seed), t0, **BG)])
    ed.baseline = {k: (statistics.fmean([s[k] for s in base_series]), statistics.pstdev([s[k] for s in base_series]) or 1e-6)
                   for k in ("shannon_path", "shannon_status", "shannon_srcip")}
    scorer = D.Scorer(os.path.join(HERE, "ml", "model"))
    tmp = os.path.join(HERE, "_cmp.log")

    rows = []
    for name, atk in SCEN.items():
        bg = bg_normal(rng, t0, **BG)
        if atk is None:
            reqs, aips = bg, set()
        else:
            a, aips = atk(rng, t0 + timedelta(minutes=5))
            reqs = bg + a
        ent = ed.detect([(ip, p, st, t) for ip, p, st, t in reqs])
        ml = ml_detect(scorer, reqs, aips, tmp) if aips else {"caught": False, "score": None, "note": "공격 없음"}
        rows.append((name, atk is not None, ent, ml))
    if os.path.exists(tmp):
        os.remove(tmp)

    def mark(caught, is_atk):
        return ("✅ 탐지" if caught else "⛔ 놓침") if is_atk else ("⚠️ 오탐" if caught else "✅ 정상")
    L = ["# 엔트로피 vs 행위 ML — 머리맞댄 비교 (같은 트래픽)", "",
         f"- 엔트로피: ZenSOC 수식(slack_alert.py) 그대로, **전역** 윈도우 100, baseline−{ed.k}σ 급락 시 탐지",
         f"- ML: e2e 고정모델(`ml/model`, 학습 {scorer.meta['n_windows']}창, high<{scorer.meta['threshold_high']}), **IP별** 15분 창",
         "- 배경: 정상 브라우징(여러 IP) 위에 공격을 얹은 하나의 전역 스트림", "",
         "| 시나리오 | 엔트로피(전역) | 행위 ML(IP별) | 설명 |", "|---|---|---|---|"]
    note = {"정상(오탐확인)": "둘 다 조용해야 정상", "대량 브루트포스": "한 IP 가 스트림 뒤덮음 → 엔트로피 급락",
            "느린 BOLA": "공격 몇 건이 정상에 묻힘 → 전역 엔트로피 안 흔들림 / IP별 ML 은 분리",
            "브라우저 블렌딩": "정상처럼 보임 — 둘 다 어려움", "IP 분산": "IP마다 몇 건 → ML 창 5건 미만, 엔트로피도 전역선 안 흔들림"}
    for name, is_atk, ent, ml in rows:
        L.append(f"| {name} | {mark(ent['caught'], is_atk)} ({ent['below_windows']}/{ent['need']}창 급락, 최대 {ent['max_drop_sigma']}σ, {ent['signal']}) | "
                 f"{mark(ml['caught'], is_atk)} ({'점수 ' + str(ml['score']) if ml['score'] is not None else ml['note']}) | {note.get(name,'')} |")
    L += ["", "## 읽는 법", "",
          "- **대량 브루트포스**: 엔트로피가 잡고 ML(IP별 15분)은 오히려 묻힐 수 있다 → 엔트로피의 강점.",
          "- **느린 BOLA / 블렌딩**: 전역 엔트로피는 정상 트래픽에 희석돼 못 본다. IP별 ML 이 잡는다 → ML 의 강점.",
          "- **IP 분산**: 둘 다 약하다(엔트로피=전역선 안 흔들림, ML=창당 5건 미만). 남은 숙제 = 계정·세션 단위.",
          "- → **두 탐지의 사각지대가 반대.** ZenSOC 에 행위 ML 층을 더하면 서로의 빈틈을 덮는다.", "",
          "> 한계: 합성 트래픽(상태코드·분포가 단순)·오프라인 재생. 실데이터·부하는 별도. 상세 근거 `../../shadow_api_monitoring/e2e_story/eval/`."]
    # 부록: 윈도우 스윕 (윈도우를 키워도 느린 공격은 못 잡음 — 집계 단위 문제)
    import window_sweep
    sw = window_sweep.main()
    L += ["", "## 부록 — \"윈도우를 늘리면 느린 공격도 잡히나?\" (window_sweep.py)", "",
          "경로 Shannon 엔트로피, 전역 윈도우 100→300→600:", "",
          "| 윈도우 | 정상(오탐) | 브루트포스 | 느린 BOLA |", "|---|---|---|---|"]
    for W, nrm, fl, sl in sw:
        L.append(f"| {W} | {nrm}σ | {fl}σ ✅ | **{sl}σ** {'✅' if sl >= ed.k else '⛔'} |")
    L += ["",
          "- 윈도우를 키우면 정상 오탐 노이즈는 조금 준다. 하지만 **느린 BOLA 는 그대로 미탐**이고 브루트포스는 오히려 약해진다.",
          "- 조용한 공격자는 전체의 ~9%(창 안에선 더 작음) → 전역 집계에선 창을 키울수록 비중이 더 작아진다.",
          "- **윈도우 크기 문제가 아니라 '집계 단위' 문제.** 조용한 한 IP 는 전역 집계로 못 분리 → IP별(ML)이 답. 과민 오탐은 ① 지속 하락 요구 ② 흔들리는 srcip 대신 안정적 경로 신호로 해결."]
    open(os.path.join(HERE, "results.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L))
    print("\n".join(L))
    write_chart(rows)


def write_chart(rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib 없음 — compare.png 건너뜀)")
        return
    names = [r[0] for r in rows]
    ent = [1 if r[2]["caught"] else 0 for r in rows]
    ml = [1 if r[3]["caught"] else 0 for r in rows]
    import numpy as np
    x = np.arange(len(names)); w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.2))
    ax.bar(x - w/2, ent, w, label="엔트로피(전역)", color="#2a78d6")
    ax.bar(x + w/2, ml, w, label="행위 ML(IP별)", color="#eb6834")
    ax.set_xticks(x); ax.set_xticklabels(names, rotation=15, ha="right", fontsize=9)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["놓침/정상", "탐지"]); ax.set_ylim(0, 1.25)
    ax.set_title("엔트로피 vs 행위 ML — 시나리오별 탐지 (사각지대가 반대)")
    ax.legend(loc="upper right"); fig.tight_layout()
    try:
        plt.rcParams["font.family"] = "Malgun Gothic"
    except Exception:
        pass
    fig.savefig(os.path.join(HERE, "compare.png"), dpi=140)
    print("저장: compare.png")


if __name__ == "__main__":
    main()
