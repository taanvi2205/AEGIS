"""Static SVG plots (§8: one plot budget, no dashboard).

SVG is emitted directly rather than through a plotting library. That keeps the
project dependency-free, which for a security project is a defensible position in
itself (§4 Rule 7): no plotting stack in the supply chain of a tool whose whole
argument is about trust boundaries.
"""

from __future__ import annotations

from pathlib import Path

W, H = 760, 420
PAD_L, PAD_R, PAD_T, PAD_B = 64, 168, 46, 54

# Colour-blind-safe qualitative palette (Okabe-Ito).
PALETTE = ("#0072b2", "#d55e00", "#009e73", "#cc79a7", "#e69f00", "#56b4e9")
INK, MUTED, GRID, BG = "#1a1a1a", "#5b5b5b", "#dcdcdc", "#ffffff"


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _frame(title: str, subtitle: str, x_label: str, y_label: str,
           x_ticks: list[tuple[float, str]], body: str) -> str:
    """Common chart chrome: background, axes, gridlines at 0/25/50/75/100%."""
    x0, y0 = PAD_L, H - PAD_B
    x1, y1 = W - PAD_R, PAD_T
    grid = []
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = y0 - frac * (y0 - y1)
        grid.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" '
                    f'stroke="{GRID}" stroke-width="1"/>')
        grid.append(f'<text x="{x0 - 10}" y="{y + 4:.1f}" text-anchor="end" '
                    f'font-size="11" fill="{MUTED}">{frac:.0%}</text>')
    for xv, label in x_ticks:
        grid.append(f'<text x="{xv:.1f}" y="{y0 + 18}" text-anchor="middle" '
                    f'font-size="11" fill="{MUTED}">{_esc(label)}</text>')
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif">
  <rect width="{W}" height="{H}" fill="{BG}"/>
  <text x="{PAD_L}" y="24" font-size="15" font-weight="600" fill="{INK}">{_esc(title)}</text>
  <text x="{PAD_L}" y="40" font-size="11.5" fill="{MUTED}">{_esc(subtitle)}</text>
  {''.join(grid)}
  <line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}" stroke="{INK}" stroke-width="1.2"/>
  <line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y1}" stroke="{INK}" stroke-width="1.2"/>
  <text x="{(x0 + x1) / 2:.0f}" y="{H - 12}" text-anchor="middle" font-size="12" fill="{MUTED}">{_esc(x_label)}</text>
  <text x="16" y="{(y0 + y1) / 2:.0f}" font-size="12" fill="{MUTED}" transform="rotate(-90 16 {(y0 + y1) / 2:.0f})" text-anchor="middle">{_esc(y_label)}</text>
  {body}
</svg>
"""


def _series(points: list[tuple[float, float]], colour: str, label: str,
            legend_y: float) -> str:
    path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colour}"/>'
                   for x, y in points)
    return (f'<polyline points="{path}" fill="none" stroke="{colour}" stroke-width="2.2" '
            f'stroke-linejoin="round"/>{dots}'
            f'<line x1="{W - PAD_R + 14}" y1="{legend_y}" x2="{W - PAD_R + 34}" y2="{legend_y}" '
            f'stroke="{colour}" stroke-width="2.2"/>'
            f'<text x="{W - PAD_R + 40}" y="{legend_y + 4}" font-size="11.5" fill="{INK}">'
            f'{_esc(label)}</text>')


def degradation_curve(result, path: str | Path) -> Path:
    """Round-by-round ASR per defense configuration - the headline chart (§7)."""
    rounds = result.rounds
    x0, y0, x1, y1 = PAD_L, H - PAD_B, W - PAD_R, PAD_T
    n = max(len(rounds) - 1, 1)

    def px(i: int) -> float:
        return x0 + (i / n) * (x1 - x0)

    def py(v: float) -> float:
        return y0 - v * (y0 - y1)

    body = []
    for k, cfg in enumerate(result.configs):
        pts = [(px(i), py(r.asr[cfg])) for i, r in enumerate(rounds)]
        body.append(_series(pts, PALETTE[k % len(PALETTE)], cfg, PAD_T + 8 + k * 18))

    step = max(1, len(rounds) // 8)
    ticks = [(px(i), str(r.round)) for i, r in enumerate(rounds) if i % step == 0]
    svg = _frame("Attack success rate under an adaptive attacker",
                 f"population {result.population}, attacker adapting against "
                 f"'{result.target}', seed {result.seed}",
                 "red-team round", "attack success rate", ticks, "".join(body))
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(svg, encoding="utf-8")
    return p


def sweep_curve(cells, tier_sets, level_names, path: str | Path) -> Path:
    """Provenance attribution rate against obfuscation level, per matcher tier."""
    x0, y0, x1, y1 = PAD_L, H - PAD_B, W - PAD_R, PAD_T
    n = max(len(level_names) - 1, 1)

    def px(i: int) -> float:
        return x0 + (i / n) * (x1 - x0)

    def py(v: float) -> float:
        return y0 - v * (y0 - y1)

    body = []
    for k, name in enumerate(tier_sets):
        pts = [(px(lv), py(next(c for c in cells if c.tier_set == name and c.level == lv)
                           .attribution_rate)) for lv in range(len(level_names))]
        body.append(_series(pts, PALETTE[k % len(PALETTE)], name, PAD_T + 8 + k * 18))

    # The block rate is flat at 100% because unattributable control-plane
    # arguments are denied by default; drawn dashed so it is not mistaken for
    # attribution.
    blk = [(px(lv), py(next(c for c in cells if c.tier_set == tier_sets[-1]
                            and c.level == lv).block_rate))
           for lv in range(len(level_names))]
    body.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in blk)}" '
                f'fill="none" stroke="{MUTED}" stroke-width="1.8" stroke-dasharray="5 4"/>'
                f'<line x1="{W - PAD_R + 14}" y1="{PAD_T + 8 + len(tier_sets) * 18}" '
                f'x2="{W - PAD_R + 34}" y2="{PAD_T + 8 + len(tier_sets) * 18}" '
                f'stroke="{MUTED}" stroke-width="1.8" stroke-dasharray="5 4"/>'
                f'<text x="{W - PAD_R + 40}" y="{PAD_T + 12 + len(tier_sets) * 18}" '
                f'font-size="11.5" fill="{INK}">block rate</text>')

    ticks = [(px(i), str(i)) for i in range(len(level_names))]
    svg = _frame("Where argument provenance stops attributing",
                 "0 identical · 1 case/spacing · 2 separators · 3 homoglyphs · "
                 "4 base64 · 5 split · 6 reference only",
                 "obfuscation level", "attribution rate", ticks, "".join(body))
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(svg, encoding="utf-8")
    return p
