"""Render the included event data as a reproducible evidence figure.

Optional visualization dependency: matplotlib. Core detection/tests use stdlib.
"""
from datetime import datetime
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt


def main():
    root = Path(__file__).parent
    rows = [json.loads(line) for line in (root / "sample_events.jsonl").read_text().splitlines() if line]
    parse = lambda row: datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
    foreground, muted, border = "#e6edf3", "#9da7b3", "#30363d"
    failure, success = "#ff8c86", "#3dd9c3"
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})
    fig, axes = plt.subplots(1, 2, figsize=(15, 5.1), gridspec_kw={"width_ratios": [1.1, 1]})
    fig.patch.set_facecolor("#0d1117")
    for axis in axes:
        axis.set_facecolor("#0d1117")
        axis.tick_params(colors=muted, labelsize=10)
        for spine in axis.spines.values():
            spine.set_color(border)
        axis.grid(axis="x", color=border, alpha=0.65, linewidth=0.6)
        axis.set_axisbelow(True)
    burst = [row for row in rows if row["src_ip"] == "203.0.113.10"]
    for kind, color, label in [(4625, failure, "Failure"), (4624, success, "Success")]:
        selected = [row for row in burst if row["event_id"] == kind]
        axes[0].scatter([parse(row) for row in selected], [1 if kind == 4625 else 0] * len(selected),
                        color=color, s=90, label=label, zorder=3, marker="o" if kind == 4624 else "X")
    axes[0].set_yticks([0, 1], ["Successful logon", "Failed logon"])
    axes[0].set_ylim(-0.6, 1.8)
    axes[0].set_title("Six failures followed by success", loc="left", color=foreground, fontsize=15, pad=25)
    axes[0].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    axes[0].xaxis.set_major_locator(mdates.SecondLocator(bysecond=[50, 55, 0, 5, 10]))
    boundary = datetime.fromisoformat("2026-11-01T09:05:00+00:00")
    axes[0].axvline(boundary, color="#d5b76a", linestyle="--", linewidth=1)
    axes[0].annotate("09:05 bucket boundary", xy=(boundary, 1.55), xytext=(7, 0),
                     textcoords="offset points", color="#d5b76a", fontsize=10)
    axes[0].set_xlabel("UTC · source 203.0.113.10 · lab-win01", color=muted, labelpad=16)
    spray = [row for row in rows if row["src_ip"] == "198.51.100.20"]
    users = sorted({row["user"] for row in spray})
    axes[1].scatter([parse(row) for row in spray], [users.index(row["user"]) for row in spray],
                    color=failure, marker="X", s=80, zorder=3)
    axes[1].set_yticks(range(len(users)), [user.split("\\")[-1] for user in users])
    axes[1].invert_yaxis()
    axes[1].set_title("Failures across eight distinct accounts", loc="left", color=foreground, fontsize=15, pad=25)
    axes[1].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    axes[1].xaxis.set_major_locator(mdates.SecondLocator(bysecond=[0, 20, 40]))
    axes[1].set_xlabel("UTC · source 198.51.100.20 · lab-win02", color=muted, labelpad=16)
    fig.text(0.065, 0.955, "AUTHENTICATION THREAT HUNTING", fontsize=11, color=success, weight="bold")
    fig.text(0.065, 0.88, "Event evidence, linked to detection logic", fontsize=23, color=foreground, weight="bold")
    fig.text(0.065, 0.025, "Source: sample_events.jsonl  |  Findings: expected_alerts.json  |  Times: 2026-11-01 UTC",
             fontsize=10, color=muted)
    fig.subplots_adjust(left=0.13, right=0.97, bottom=0.21, top=0.71, wspace=0.38)
    fig.savefig(root / "evidence-overview.png", dpi=150, facecolor=fig.get_facecolor())
    plt.close(fig)


if __name__ == "__main__":
    main()
