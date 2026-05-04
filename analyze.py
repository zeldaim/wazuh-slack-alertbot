import pandas as pd
import matplotlib.pyplot as plt
import json

# 데이터 로드
records = []
with open("entropy_log.jsonl", "r") as f:
    for line in f:
        records.append(json.loads(line))

df = pd.DataFrame(records)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["index"] = range(len(df))

# 정상/공격 구간 구분
df["phase"] = df["index"].apply(lambda x: "normal" if x < 293 else "attack")

# 그래프 그리기
fig, axes = plt.subplots(2, 2, figsize=(14, 8))
fig.suptitle("ZenSOC — Entropy Analysis (Normal vs Attack)", fontsize=14)

metrics = [
    ("shannon_rule_id", "Shannon Entropy — Rule ID"),
    ("shannon_level",   "Shannon Entropy — Level"),
    ("shannon_srcip",   "Shannon Entropy — Source IP"),
    ("apen_level",      "Approximate Entropy — Level"),
]

colors = {"normal": "steelblue", "attack": "crimson"}

for ax, (col, title) in zip(axes.flatten(), metrics):
    for phase, group in df.groupby("phase"):
        ax.plot(group["index"], group[col], label=phase,
                color=colors[phase], alpha=0.7, linewidth=0.8)
    ax.axvline(x=293, color="black", linestyle="--", linewidth=1, label="attack start")
    ax.set_title(title)
    ax.set_xlabel("Alert Index")
    ax.set_ylabel("Entropy")
    ax.legend()

plt.tight_layout()
plt.savefig("entropy_analysis.png", dpi=150)
print("저장 완료: entropy_analysis.png")
