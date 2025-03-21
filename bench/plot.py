#!/usr/bin/env python3
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
src = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "results.json"
dst = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "overhead.svg"

data = json.loads(src.read_text())
results = data["results"]

labels = [r["label"] for r in results]
p50 = [r["p50"] for r in results]
p99 = [r["p99"] for r in results]

W, H = 720, 420
pad_l, pad_b, pad_t, pad_r = 70, 70, 60, 30
plot_w, plot_h = W - pad_l - pad_r, H - pad_t - pad_b
vmax = max(p99 + [1.0]) * 1.15


def y(v):
    return pad_t + plot_h - (v / vmax) * plot_h


group_w = plot_w / len(labels)
bar_w = group_w * 0.28
C50, C99 = "#2563eb", "#f59e0b"

svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
       f'font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif">']
svg.append(f'<rect width="{W}" height="{H}" fill="white"/>')
svg.append(f'<text x="{W/2}" y="30" text-anchor="middle" font-size="18" '
           f'font-weight="600">Workload startup: attestation overhead</text>')
svg.append(f'<text x="{W/2}" y="48" text-anchor="middle" font-size="12" '
           f'fill="#555">software backend, {data["runs"]} runs, lower is better</text>')

for i in range(5):
    v = vmax * i / 4
    yy = y(v)
    svg.append(f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{W-pad_r}" y2="{yy:.1f}" '
               f'stroke="#eee"/>')
    svg.append(f'<text x="{pad_l-8}" y="{yy+4:.1f}" text-anchor="end" '
               f'font-size="11" fill="#555">{v:.1f}</text>')
svg.append(f'<text x="18" y="{pad_t+plot_h/2}" font-size="12" fill="#555" '
           f'transform="rotate(-90 18 {pad_t+plot_h/2})" text-anchor="middle">'
           f'startup time (ms)</text>')

for i, lab in enumerate(labels):
    cx = pad_l + group_w * (i + 0.5)
    x50 = cx - bar_w - 2
    x99 = cx + 2
    svg.append(f'<rect x="{x50:.1f}" y="{y(p50[i]):.1f}" width="{bar_w:.1f}" '
               f'height="{pad_t+plot_h-y(p50[i]):.1f}" fill="{C50}"/>')
    svg.append(f'<rect x="{x99:.1f}" y="{y(p99[i]):.1f}" width="{bar_w:.1f}" '
               f'height="{pad_t+plot_h-y(p99[i]):.1f}" fill="{C99}"/>')
    svg.append(f'<text x="{x50+bar_w/2:.1f}" y="{y(p50[i])-6:.1f}" '
               f'text-anchor="middle" font-size="10">{p50[i]:.2f}</text>')
    svg.append(f'<text x="{x99+bar_w/2:.1f}" y="{y(p99[i])-6:.1f}" '
               f'text-anchor="middle" font-size="10">{p99[i]:.2f}</text>')
    svg.append(f'<text x="{cx:.1f}" y="{pad_t+plot_h+20:.1f}" '
               f'text-anchor="middle" font-size="12">{lab}</text>')

lx, ly = W - pad_r - 150, pad_t + 6
svg.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" fill="{C50}"/>')
svg.append(f'<text x="{lx+18}" y="{ly+11}" font-size="12">p50</text>')
svg.append(f'<rect x="{lx+70}" y="{ly}" width="12" height="12" fill="{C99}"/>')
svg.append(f'<text x="{lx+88}" y="{ly+11}" font-size="12">p99</text>')

svg.append('</svg>')
dst.write_text("\n".join(svg))
print(f"wrote {dst} ({len(labels)} series)")
