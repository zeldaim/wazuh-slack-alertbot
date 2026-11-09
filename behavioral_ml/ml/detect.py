#!/usr/bin/env python3
"""실시간 ML 탐지기 — 1분마다 최근 N분 접근 로그를 IP 별로 점수 매기고, 이상이면 Wazuh 가 읽는 JSON 줄을 남긴다.

  python3 detect.py --log ~/soc-lab/weblogs/access.log --alerts ~/soc-lab/weblogs/ml_alerts.json \
                    --scores ~/e2e/ml_scores.jsonl [--window 15] [--every 60] [--once]
  python3 detect.py --replay <access.log>     # 저장된 로그를 고정 창으로 점수만 (평가용)

흐름: access.log → (이 스크립트) → ml_alerts.json → Wazuh localfile(json) → 규칙 100950/100951 → custom-eda → EDA
대응(차단 여부)은 여기서 정하지 않는다 — Wazuh 규칙 레벨과 EDA 허용목록이 정한다 (탐지와 대응 분리).
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import joblib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import FEATURES, featurize, parse, windows  # noqa: E402

LABEL = {"n_req": "요청 수", "uniq_path_ratio": "경로 다양성", "top_tpl_share": "한 API 집중", "seq_id_run": "연속 ID 열거", "seq_ratio": "열거 비율",
         "id_span_log": "ID 종류", "gap_mean_log": "간격", "gap_cv": "간격 불규칙성", "err_ratio": "오류 비율",
         "api_ratio": "API 비율", "static_ratio": "정적 파일 비율", "n_ua": "UA 종류", "offspec_ratio": "명세 밖 비율"}


class Scorer:
    def __init__(self, model_dir):
        self.m = joblib.load(os.path.join(model_dir, "model.joblib"))
        with open(os.path.join(model_dir, "model_meta.json"), encoding="utf-8") as f:
            self.meta = json.load(f)
        assert self.meta["features"] == FEATURES, "모델과 특징 순서가 다름 — 다시 학습"
        self.med = np.array(self.meta["median"])
        self.scale = np.array(self.meta["scale"])

    def score(self, ft):
        x = np.array([[ft[k] for k in FEATURES]])
        s = float(self.m.decision_function(x)[0])
        z = (x[0] - self.med) / self.scale
        top = sorted(zip(FEATURES, x[0], z), key=lambda t: -abs(t[2]))[:3]
        sev = "high" if s < self.meta["threshold_high"] else "medium" if s < self.meta["threshold_medium"] else "normal"
        why = ", ".join(f"{LABEL[k]} {v:g}(z{zz:+.1f})" for k, v, zz in top)
        return s, sev, why


def tick(sc, a, last_alert):
    now = time.time()
    rows = [r for r in parse(a.log) if r[1] >= now - a.window * 60]
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r[0]].append(r)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for ip, reqs in by_ip.items():
        if len(reqs) < a.min_req:
            continue
        ft = featurize(reqs)
        s, sev, why = sc.score(ft)
        rec = {"timestamp": stamp, "srcip": ip, "ml_score": round(s, 4), "severity": sev, "n_req": ft["n_req"],
               "window_min": a.window, "why": why, "features": {k: round(v, 4) for k, v in ft.items()}}
        with open(a.scores, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        # 같은 IP 는 cooldown 분에 한 번만 경보 (EDA throttle 과 별개로 Wazuh 경보 홍수 방지)
        if sev != "normal" and now - last_alert.get((ip, sev), 0) >= a.cooldown * 60:
            last_alert[(ip, sev)] = now
            alert = {"source": "ml-detector", "severity": sev, "srcip": ip, "ml_score": f"{s:.4f}",
                     "threshold": f"{sc.meta['threshold_high' if sev == 'high' else 'threshold_medium']:.4f}",
                     "n_req": str(ft["n_req"]), "window_min": str(a.window), "why": why,
                     "summary": f"{a.window}분 동안 {ft['n_req']}건 · {why}"}
            with open(a.alerts, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
            print(f"[ML] {stamp} {ip} {sev} score={s:.4f} · {why}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.join(HERE, "model"))
    ap.add_argument("--log")
    ap.add_argument("--alerts")
    ap.add_argument("--scores", default=os.path.expanduser("~/e2e/ml_scores.jsonl"))
    ap.add_argument("--window", type=int, default=15)
    ap.add_argument("--min-req", type=int, default=5)
    ap.add_argument("--every", type=int, default=60)
    ap.add_argument("--cooldown", type=int, default=10)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--replay")
    a = ap.parse_args()
    sc = Scorer(a.model)

    if a.replay:
        for ip, start, ft in windows(parse(a.replay), a.window, a.min_req):
            s, sev, why = sc.score(ft)
            print(f"{datetime.fromtimestamp(start, timezone.utc):%m-%d %H:%M} {ip:16s} n={ft['n_req']:<4} {s:+.4f} {sev:7s} {why}")
        return

    os.makedirs(os.path.dirname(os.path.abspath(a.scores)), exist_ok=True)
    print(f"[ML] 시작 — 창 {a.window}분 · {a.every}초마다 · 임계값 high<{sc.meta['threshold_high']} "
          f"medium<{sc.meta['threshold_medium']} · 학습 창 {sc.meta['n_windows']}개", flush=True)
    last = {}
    while True:
        try:
            tick(sc, a, last)
        except FileNotFoundError:
            pass
        if a.once:
            break
        time.sleep(a.every)


if __name__ == "__main__":
    main()
