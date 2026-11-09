#!/usr/bin/env python3
"""ZenSOC 엔트로피 탐지를 '전역 스트림'에 적용 — 행위 ML(IP별)과 머리맞대기 위한 기준선.

ZenSOC(slack_alert.py)는 최근 100개 **경보** 스트림에서 Shannon(rule_id/level/srcip)·ApEn(level)을 재고,
공격(브루트포스)이 들어오면 한 rule_id 가 스트림을 뒤덮어 **다양성이 급락**하는 것으로 탐지한다.
여기서는 같은 수식(아래 shannon_entropy·approximate_entropy 는 slack_alert.py 에서 그대로 가져옴)을
원시 HTTP 트래픽 윈도우에 적용한다. 매핑: rule_id→경로 틀, level→상태코드, srcip→srcip.

핵심: **전역**(모든 IP 섞인) 슬라이딩 윈도우 — ZenSOC 와 동일. 그래서 한 IP 의 조용한 공격은
정상 트래픽의 높은 다양성에 묻힌다(= ZenSOC 의 구조적 사각지대, compare.py 가 증명).
"""
import math
import re
from collections import Counter, deque

NUM = re.compile(r"/\d+(?=/|$)")


def template(path):
    return NUM.sub("/{id}", path.split("?", 1)[0])


# ── 아래 두 함수는 ZenSOC slack_alert.py 와 동일 (수식 보존) ──
def shannon_entropy(values):
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def approximate_entropy(values, m=2, r_ratio=0.2):
    N = len(values)
    if N < m + 2:
        return 0.0
    mean = sum(values) / N
    std = (sum((v - mean) ** 2 for v in values) / N) ** 0.5
    r = r_ratio * std if std > 0 else 1e-6

    def phi(m_len):
        templates = [values[i:i + m_len] for i in range(N - m_len + 1)]
        counts = []
        for t in templates:
            cnt = sum(1 for s in templates if max(abs(t[k] - s[k]) for k in range(m_len)) <= r)
            counts.append(cnt / (N - m_len + 1))
        return sum(math.log(c) for c in counts if c > 0) / (N - m_len + 1)

    return abs(phi(m) - phi(m + 1))


def window_entropy(window):
    """최근 요청 윈도우(각 (ip, template, status)) → ZenSOC 식 4개 엔트로피."""
    return {
        "shannon_path": shannon_entropy([w[1] for w in window]),
        "shannon_status": shannon_entropy([w[2] for w in window]),
        "shannon_srcip": shannon_entropy([w[0] for w in window]),
        "apen_status": approximate_entropy([w[2] for w in window]),
    }


class EntropyDetector:
    """전역 슬라이딩 윈도우(기본 100) 엔트로피. baseline(정상) 대비 Shannon 이 급락하면 공격."""

    def __init__(self, window=100, k=3.0):
        self.window = window
        self.k = k            # baseline 평균 - k·표준편차 아래로 내려가면 경보
        self.baseline = None  # {key: (mean, std)}

    def _series(self, requests):
        """요청 리스트 → 각 스텝의 윈도우 엔트로피 시계열. requests: [(ip, path, status, t)] 시간순."""
        win, out = deque(maxlen=self.window), []
        for ip, path, status, t in requests:
            win.append((ip, template(path), int(status)))
            if len(win) >= min(self.window, 20):
                out.append(window_entropy(list(win)))
        return out

    def fit_baseline(self, normal_requests):
        import statistics
        series = self._series(normal_requests)
        keys = ("shannon_path", "shannon_status", "shannon_srcip")
        self.baseline = {k: (statistics.fmean([s[k] for s in series]),
                             statistics.pstdev([s[k] for s in series]) or 1e-6) for k in keys}
        return self.baseline

    # 트리거 신호 = 내용 다양성(경로·상태). ZenSOC 의 rule_id→경로, level→상태 대응.
    #   srcip 는 공격자 요청 '속도'에 따라 흔들려(단일 IP 가 창을 점유하면 하락) 참고로만 보고.
    TRIGGER = ("shannon_path", "shannon_status")

    def detect(self, requests, min_frac=0.10, min_windows=8):
        """공격 탐지 — 순간 1회가 아니라 **지속적 하락**일 때만(ZenSOC 도 경보가 쌓여야 요약 전송).
        트리거 신호가 baseline−kσ 아래로 내려간 윈도우가 전체의 min_frac(또는 min_windows) 이상이면 탐지."""
        series = self._series(requests)
        n = len(series) or 1
        need = max(min_windows, int(n * min_frac))
        best = None
        for k, (mean, std) in self.baseline.items():
            below = sum(1 for s in series if (mean - s[k]) / std >= self.k)
            mx = max((((mean - s[k]) / std) for s in series), default=0.0)
            if k in self.TRIGGER and (best is None or below > best[1]):
                best = (k, below, mx)
            if k == "shannon_srcip":
                self._srcip_below = below
        caught = best is not None and best[1] >= need
        return {"caught": caught, "signal": best[0] if best else None,
                "below_windows": best[1] if best else 0, "need": need,
                "max_drop_sigma": round(best[2], 1) if best else None,
                "srcip_below": getattr(self, "_srcip_below", 0)}
