#!/usr/bin/env python3
"""윈도우 크기를 늘리면 느린 공격을 잡나? — 전역 경로 Shannon 엔트로피의 윈도우 스윕.

  python window_sweep.py

결과(2026-11-09): 윈도우를 키우면 정상 오탐 노이즈는 약간 줄지만(4.1→3.9σ),
느린 BOLA 는 2.0σ 로 **그대로**(미탐)이고 브루트포스는 오히려 약해진다(39→25σ).
→ 조용한 한 IP 는 전역 집계에서 창을 키울수록 비중이 더 작아진다. 윈도우 문제가 아니라 '집계 단위' 문제.
"""
import os
import random
import statistics as st
import sys
from collections import deque
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import entropy_detect as E   # noqa: E402
import compare as C          # noqa: E402

BG = dict(minutes=30, n_ips=12, rate_per_min=8)


def path_series(reqs, W):
    win, out = deque(maxlen=W), []
    for ip, p, s, t in sorted(reqs, key=lambda r: r[3]):
        win.append(E.template(p))
        if len(win) >= min(W, 20):
            out.append(E.shannon_entropy(list(win)))
    return out


def main():
    t0 = datetime(2026, 11, 10, tzinfo=timezone.utc)
    print(f"{'window':>6} | {'정상 최대σ':>9} | {'브루트포스':>9} | {'느린BOLA':>8}")
    rows = []
    for W in (100, 300, 600):
        base = []
        for s in range(6):
            base += path_series(C.bg_normal(random.Random(100 + s), t0, **BG), W)
        mean, sd = st.fmean(base), (st.pstdev(base) or 1e-6)
        sig = lambda ser: round(max((mean - v) / sd for v in ser), 1)
        rng = random.Random(7)
        nrm = sig(path_series(C.bg_normal(rng, t0, **BG), W))
        bg = C.bg_normal(rng, t0, **BG); a, _ = C.atk_flood(rng, t0 + timedelta(minutes=5)); fl = sig(path_series(bg + a, W))
        bg = C.bg_normal(rng, t0, **BG); a, _ = C.atk_slow(rng, t0 + timedelta(minutes=5)); sl = sig(path_series(bg + a, W))
        print(f"{W:>6} | {nrm:>9} | {fl:>9} | {sl:>8}")
        rows.append((W, nrm, fl, sl))
    return rows


if __name__ == "__main__":
    main()
