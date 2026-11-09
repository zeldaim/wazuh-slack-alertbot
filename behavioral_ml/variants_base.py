#!/usr/bin/env python3
"""공격 변종 생성기 — 느린 BOLA 의 회피 기법별로 Apache combined 로그 세션을 만든다.

모델을 '고정한 뒤' 평가하기 위한 것. 변종은 특징을 겨냥해 만들지 않고, 공격자가 실제로 쓰는
회피 기법(순서 섞기 · 여러 API 분산 · 정상 트래픽에 섞기 · 더 느리게 · IP 분산)으로 만든다.
못 잡는 변종은 그대로 결과(한계)로 보고한다.

  python variants.py --out-dir sessions --n 40 --seed 100

각 변종마다 n 개 세션(서로 다른 seed·시작 ID·시간)을 만들어, 탐지율을 '몇/몇' 로 잴 수 있게 한다.
합성 IP(10.9.x.x)·합성 데이터만 쓴다. 실제 로그·실제 IP 는 들어가지 않는다.
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

UA_BOT = ["python-requests/2.32", "curl/8.5.0", "Go-http-client/2.0", "okhttp/4.12"]
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
NORMAL_PAGES = ["/", "/products.php", "/api/v2/products", "/api/v2/products/{r}", "/api/v2/cart",
                "/assets/style.css", "/assets/app.js", "/api/v2/users/me", "/api/v2/categories"]
SPEC_TARGET = "/api/v2/orders/{id}"      # 명세 안 API (BOLA 대상) — 서명·Shadow 규칙에 안 걸림
OTHER_TARGETS = ["/api/v2/orders/{id}", "/api/v2/products/{id}", "/api/v2/users/{id}", "/api/v2/invoices/{id}"]


def line(ip, t, path, ua, status=200):
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" {status} 312 "-" "{ua}"'


def gen_session(variant, rng, t0, base_id):
    """한 세션 → (lines, 공격 IP 목록). 15분 창 하나에 담기도록."""
    L, ips = [], set()
    ip = f"10.9.{rng.randint(1, 254)}.{rng.randint(2, 254)}"

    def seq_ids(n):
        return list(range(base_id, base_id + n))

    if variant == "V1_sequential":          # 기준: 순차 BOLA (모델을 고칠 때 본 형태)
        ids, ua, gap = seq_ids(25), rng.choice(UA_BOT), (14, 26)
        for i in ids:
            t0 += timedelta(seconds=rng.uniform(*gap)); L.append(line(ip, t0, SPEC_TARGET.format(id=i), ua)); ips.add(ip)

    elif variant == "V2_random_order":       # ID 를 무작위 순서로 (연속 열거 특징 무력화)
        ids = seq_ids(25); rng.shuffle(ids); ua = rng.choice(UA_BOT)
        for i in ids:
            t0 += timedelta(seconds=rng.uniform(14, 26)); L.append(line(ip, t0, SPEC_TARGET.format(id=i), ua)); ips.add(ip)

    elif variant == "V3_multi_api":          # 여러 API 에 나눠 (한 API 집중 무력화)
        ua = rng.choice(UA_BOT)
        for k in range(25):
            tgt = rng.choice(OTHER_TARGETS); t0 += timedelta(seconds=rng.uniform(14, 26))
            L.append(line(ip, t0, tgt.format(id=base_id + k), ua)); ips.add(ip)

    elif variant == "V4_blend_browser":      # 브라우저 UA + 정상 페이지에 공격을 섞음
        for k in range(40):
            t0 += timedelta(seconds=rng.uniform(8, 20))
            if rng.random() < 0.4:
                L.append(line(ip, t0, SPEC_TARGET.format(id=base_id + k), UA_BROWSER))
            else:
                p = rng.choice(NORMAL_PAGES).replace("{r}", str(rng.randint(1, 50)))
                L.append(line(ip, t0, p, UA_BROWSER))
            ips.add(ip)

    elif variant == "V5_very_slow":          # 더 느리게 (60~110초), 요청 수 적게
        ids, ua = seq_ids(10), rng.choice(UA_BOT)
        for i in ids:
            t0 += timedelta(seconds=rng.uniform(60, 110)); L.append(line(ip, t0, SPEC_TARGET.format(id=i), ua)); ips.add(ip)

    elif variant == "V6_ip_distributed":     # 여러 IP 로 분산 (창당 요청 수를 5건 미만으로)
        ua = rng.choice(UA_BOT)
        for k in range(25):
            dip = f"10.9.{rng.randint(1, 254)}.{rng.randint(2, 254)}"
            t0 += timedelta(seconds=rng.uniform(14, 26)); L.append(line(dip, t0, SPEC_TARGET.format(id=base_id + k), ua)); ips.add(dip)

    elif variant == "V7_combined":           # 무작위 순서 + 여러 API + 브라우저 + 정상 섞기 (결합 회피)
        for k in range(40):
            t0 += timedelta(seconds=rng.uniform(10, 24))
            if rng.random() < 0.45:
                tgt = rng.choice(OTHER_TARGETS); L.append(line(ip, t0, tgt.format(id=rng.randint(base_id, base_id + 300)), UA_BROWSER))
            else:
                p = rng.choice(NORMAL_PAGES).replace("{r}", str(rng.randint(1, 50)))
                L.append(line(ip, t0, p, UA_BROWSER))
            ips.add(ip)

    elif variant == "B_normal":              # 대조군: 정상 사용자 (공격 아님 — 오탐 확인용)
        for k in range(rng.randint(15, 45)):
            t0 += timedelta(seconds=rng.expovariate(1 / 22))
            p = rng.choice(NORMAL_PAGES).replace("{r}", str(rng.randint(1, 50)))
            L.append(line(ip, t0, p, UA_BROWSER)); ips.add(ip)

    else:
        raise ValueError(variant)
    return L, sorted(ips)


VARIANTS = ["V1_sequential", "V2_random_order", "V3_multi_api", "V4_blend_browser",
            "V5_very_slow", "V6_ip_distributed", "V7_combined", "B_normal"]

DESC = {
    "V1_sequential": "순차 BOLA (모델 조정 때 본 형태) — 기준선",
    "V2_random_order": "ID 무작위 순서 — 연속 열거 회피",
    "V3_multi_api": "여러 API 에 분산 — 한 API 집중 회피",
    "V4_blend_browser": "브라우저 UA + 정상 페이지에 섞음",
    "V5_very_slow": "60~110초 간격, 요청 10건 — 더 느리게",
    "V6_ip_distributed": "여러 IP 로 분산 — 창당 5건 미만 노림",
    "V7_combined": "무작위+다API+브라우저+정상 섞기 (결합)",
    "B_normal": "정상 사용자 (대조군, 오탐 확인)",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions"))
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=100)
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    manifest = {"n_per_variant": a.n, "seed": a.seed, "desc": DESC, "variants": {}}
    for v in VARIANTS:
        rng = random.Random(a.seed ^ hash(v) & 0xffffffff)
        sessions = []
        for s in range(a.n):
            t0 = datetime(2026, 11, 10, 0, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=17 * s)
            lines, ips = gen_session(v, rng, t0, base_id=rng.randint(1000, 5000))
            sessions.append({"lines": lines, "attacker_ips": ips})
        with open(os.path.join(a.out_dir, f"{v}.jsonl"), "w", encoding="utf-8") as f:
            for s in sessions:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        manifest["variants"][v] = {"desc": DESC[v], "n_sessions": len(sessions),
                                   "is_attack": not v.startswith("B_")}
    with open(os.path.join(a.out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print(f"[variants] {len(VARIANTS)}종 × {a.n}세션 → {a.out_dir}")


if __name__ == "__main__":
    main()
