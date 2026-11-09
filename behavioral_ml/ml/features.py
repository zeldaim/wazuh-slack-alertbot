#!/usr/bin/env python3
"""접근 로그(Apache combined) → 출발지 IP × 시간 창 별 행위 특징.

느린 공격(low-and-slow)은 요청 하나하나는 정상이라 서명 규칙(1009xx)·명세 규칙(1005xx)·빈도 규칙(초당 N건)을
모두 통과한다. 대신 '한 IP 가 일정 시간 동안 한 행동의 모양'은 다르다 → 그 모양을 숫자로 만든다.

  python3 features.py extract <access.log> [--window 15] [--out features.csv] [--no-ip]

학습(train.py)과 실시간 탐지(detect.py)가 같은 함수를 쓴다. 표준 라이브러리만 사용.
"""
import argparse
import csv
import math
import os
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "[^"]*" "([^"]*)"')
NUM = re.compile(r"/\d+(?=/|$)")
STATIC = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", re.I)

# 특징 이름 — 순서가 모델 입력 순서다 (바꾸면 다시 학습)
FEATURES = [
    "n_req",            # 창 안 요청 수
    "uniq_path_ratio",  # 서로 다른 경로 / 요청 수 (열거·스캔이면 1 에 가깝다)
    "top_tpl_share",    # 가장 많이 부른 경로 틀(/x/{n}) 비율 (한 API 만 두드리면 1)
    "seq_id_run",       # 같은 틀에서 숫자 ID 가 1 씩 늘어난 최장 연속 길이 (BOLA 열거)
    "seq_ratio",        # 위 연속 길이 / 요청 수 — 창 안 요청 대부분이 열거인가
    "id_span_log",      # 같은 틀에서 본 숫자 ID 개수 log1p
    "gap_mean_log",     # 요청 간격 평균(초) log1p
    "gap_cv",           # 요청 간격 변동계수 (기계적으로 일정하면 작다)
    "err_ratio",        # 4xx·5xx 비율
    "api_ratio",        # /api 요청 비율
    "static_ratio",     # 정적 파일(css·js·이미지) 비율 — 브라우저 사용자는 높다
    "n_ua",             # User-Agent 종류 수
    "offspec_ratio",    # /api 요청 중 명세(openapi.yaml)에 없는 것 비율 — 1 이상이면 Shadow API 규칙이 이미 잡는다
]

# 명세(허용 목록) — openapi.yaml 의 paths 를 정규식으로. 의존성 없이 들여쓰기만 보고 읽는다
_HERE = os.path.dirname(os.path.abspath(__file__))
SPEC_CANDIDATES = [os.environ.get("E2E_SPEC", ""), os.path.join(_HERE, "openapi.yaml"),
                   os.path.join(_HERE, "..", "..", "team_src", "web", "src", "public", "docs", "openapi.yaml")]
SPEC = []


def load_spec(path=None):
    path = path or next((p for p in SPEC_CANDIDATES if p and os.path.exists(p)), None)
    if not path:
        raise SystemExit("openapi.yaml 을 찾을 수 없음 (E2E_SPEC 로 지정)")
    out, cur, inside = [], None, False
    for line in open(path, encoding="utf-8"):
        if re.match(r"^paths:\s*$", line):
            inside = True
            continue
        if inside and re.match(r"^\S", line):
            break
        m = re.match(r"^  (/\S*):\s*$", line)
        if inside and m:
            cur = "^" + re.sub(r"\\{[^}]+\\}", "[^/]+", re.escape(m.group(1))) + "/*$"
            continue
        m = re.match(r"^    (get|post|put|patch|delete|head|options):", line)
        if inside and cur and m:
            out.append((m.group(1).upper(), re.compile(cur)))
    SPEC[:] = out
    return path


def offspec(method, path):
    if not SPEC:
        load_spec()
    return not any(meth == method and rx.match(path) for meth, rx in SPEC)


def parse(path):
    """→ (ip, epoch, method, path, status, ua) 를 시간 순으로. 형식 안 맞는 줄은 건너뜀."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            ip, ts, meth, url, st, _, ua = m.groups()
            try:   # 팀 웹은 11-09 부터 밀리초가 붙은 형식(10:36:08.876 +0900)도 섞여 있다
                t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S.%f %z" if "." in ts else "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                continue
            out.append((ip, t, meth, url.split("?", 1)[0], int(st), ua))
    out.sort(key=lambda r: r[1])
    return out


def template(p):
    return NUM.sub("/{n}", p)


def seq_run(ids):
    """정렬하지 않은 호출 순서 그대로 +1 연속(가장 긴 것). 정렬 후 연속도 같이 보고 큰 쪽."""
    def run(seq):
        best = cur = 1 if seq else 0
        for a, b in zip(seq, seq[1:]):
            cur = cur + 1 if b == a + 1 else 1
            best = max(best, cur)
        return best
    return max(run(ids), run(sorted(set(ids))))


def featurize(reqs):
    """한 IP 의 한 창 요청 목록 → 특징 dict"""
    n = len(reqs)
    paths = [r[3] for r in reqs]
    tpls = defaultdict(list)
    for p in paths:
        tpls[template(p)].append(p)
    top = max(tpls.values(), key=len)
    best_run, best_span = 0, 0
    for t, ps in tpls.items():
        ids = [int(NUM.findall(p)[-1][1:]) for p in ps if NUM.search(p)]   # 경로의 마지막 숫자 = 객체 ID
        if ids:
            best_run = max(best_run, seq_run(ids))
            best_span = max(best_span, len(set(ids)))
    api = [r for r in reqs if r[3].startswith("/api")]
    ts = [r[1] for r in reqs]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    gm = statistics.fmean(gaps) if gaps else 0.0
    cv = (statistics.pstdev(gaps) / gm) if len(gaps) > 1 and gm > 0 else 0.0
    return {
        "n_req": n,
        "uniq_path_ratio": len(set(paths)) / n,
        "top_tpl_share": len(top) / n,
        "seq_id_run": best_run,
        "seq_ratio": best_run / n,
        "id_span_log": math.log1p(best_span),
        "gap_mean_log": math.log1p(gm),
        "gap_cv": min(cv, 10.0),
        "err_ratio": sum(1 for r in reqs if r[4] >= 400) / n,
        "api_ratio": sum(1 for p in paths if p.startswith("/api")) / n,
        "static_ratio": sum(1 for p in paths if STATIC.search(p)) / n,
        "n_ua": len({r[5] for r in reqs}),
        "offspec_ratio": (sum(1 for r in api if offspec(r[2], r[3])) / len(api)) if api else 0.0,
    }


def windows(rows, window_min=15, min_req=5):
    """고정 창(window_min 분)으로 잘라 IP 별 특징. 요청이 min_req 미만인 창은 판단 불가로 뺀다."""
    w = window_min * 60
    buckets = defaultdict(list)
    for r in rows:
        buckets[(r[0], int(r[1] // w))].append(r)
    for (ip, b), reqs in sorted(buckets.items(), key=lambda kv: kv[0][1]):
        if len(reqs) >= min_req:
            yield ip, b * w, featurize(reqs)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    e = sp.add_parser("extract")
    e.add_argument("log")
    e.add_argument("--window", type=int, default=15)
    e.add_argument("--min-req", type=int, default=5)
    e.add_argument("--out", default="-")
    e.add_argument("--no-ip", action="store_true", help="IP 를 빼고 저장 (학습 데이터를 레포·다른 VM 으로 옮길 때)")
    a = ap.parse_args()
    rows = parse(a.log)
    f = sys.stdout if a.out == "-" else open(a.out, "w", newline="", encoding="utf-8")
    w = csv.writer(f, lineterminator="\n")
    w.writerow(([] if a.no_ip else ["ip"]) + ["window_start"] + FEATURES)
    n = 0
    for ip, start, ft in windows(rows, a.window, a.min_req):
        w.writerow(([] if a.no_ip else [ip]) + [int(start)] + [round(ft[k], 4) for k in FEATURES])
        n += 1
    print(f"[features] 줄 {len(rows)} → 창 {n}개 ({a.window}분, 요청 {a.min_req}건 이상)", file=sys.stderr)


if __name__ == "__main__":
    main()
