"""HTML reporter — generates a self-contained, portfolio-quality scan report."""
from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from modules.base import ModuleResult
from reports.base import BaseReporter

_FRAMEWORK_VERSION = "1.0.0"

_SEV_CLASSES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

_DIFFICULTY_CLASSES = {
    "TRIVIAL":  "trivial",
    "EASY":     "easy",
    "MODERATE": "moderate",
    "HARD":     "hard",
    "NONE":     "none",
}

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

_CSS = """\
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;
  --border:#30363d;--border2:#21262d;
  --text:#e6edf3;--muted:#7d8590;
  --red:#f85149;--red-d:rgba(248,81,73,.14);
  --orange:#e3b341;--orange-d:rgba(227,179,65,.12);
  --blue:#58a6ff;--blue-d:rgba(88,166,255,.12);
  --green:#3fb950;--green-d:rgba(63,185,80,.1);
  --critical:#ff4444;--critical-d:rgba(255,68,68,.14);
  --accent:#cc3333;
  --font:'Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'Cascadia Code','Fira Code',Consolas,monospace;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--font);background:var(--bg);color:var(--text);
  line-height:1.6;font-size:14px;-webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
code,pre,.mono{font-family:var(--mono);font-size:12px}

/* ── Layout ─────────────────────────────────────────────── */
.page{max-width:1100px;margin:0 auto;padding:32px 20px 64px}

/* ── Header ─────────────────────────────────────────────── */
.header{
  background:var(--surface);
  border:1px solid var(--border);
  border-top:3px solid var(--accent);
  border-radius:8px;
  padding:20px 24px;
  margin-bottom:20px;
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:16px;
  flex-wrap:wrap;
}
.hdr-brand{font-size:11px;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;color:var(--accent);margin-bottom:4px}
.hdr-title{font-size:20px;font-weight:700;letter-spacing:-.01em;color:var(--text)}
.hdr-sub{font-size:12px;color:var(--muted);margin-top:2px}
.hdr-target{
  font-family:var(--mono);font-size:12px;color:var(--text);
  margin-top:8px;word-break:break-all;
  background:var(--surface2);border:1px solid var(--border2);
  border-radius:4px;padding:5px 10px;display:inline-block;max-width:100%;
}
.hdr-right{text-align:right;display:flex;flex-direction:column;
  align-items:flex-end;gap:10px}
.verdict{
  display:inline-block;padding:5px 14px;border-radius:4px;
  font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
}
.verdict.vuln{background:var(--red-d);color:var(--red);border:1px solid var(--red)}
.verdict.clean{background:var(--green-d);color:var(--green);border:1px solid var(--green)}
.hdr-meta{display:flex;gap:20px;flex-wrap:wrap;justify-content:flex-end}
.hdr-meta-item{display:flex;flex-direction:column;align-items:flex-end}
.hdr-meta-item .lbl{font-size:10px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);margin-bottom:1px}
.hdr-meta-item .val{font-size:12px;color:var(--text);font-family:var(--mono)}

/* ── Stats row ───────────────────────────────────────────── */
.stats-row{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(125px,1fr));
  gap:12px;margin-bottom:20px;
}
.stat-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:14px 16px;text-align:center;
  transition:border-color .15s;
}
.stat-card:hover{border-color:var(--muted)}
.stat-card.s-vuln{border-color:var(--red)}
.stat-card.s-clean{border-color:var(--green)}
.stat-value{font-size:26px;font-weight:700;line-height:1;color:var(--text)}
.stat-value.c-red{color:var(--red)}
.stat-value.c-green{color:var(--green)}
.stat-value.c-blue{color:var(--blue)}
.stat-value.c-orange{color:var(--orange)}
.stat-value.c-critical{color:var(--critical)}
.stat-label{font-size:10px;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em;margin-top:4px}

/* ── Severity distribution ───────────────────────────────── */
.sev-dist{
  background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:16px 20px;margin-bottom:20px;
}
.sev-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.sev-row:last-child{margin-bottom:0}
.sev-lbl{
  font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;width:68px;text-align:right;
}
.sev-track{flex:1;height:6px;background:var(--surface2);border-radius:3px;overflow:hidden}
.sev-fill{height:100%;border-radius:3px;transition:width .4s}
.sev-n{font-size:11px;color:var(--muted);width:24px;text-align:right}
.c-critical{color:var(--critical)}.fill-critical{background:var(--critical)}
.c-high{color:var(--red)}        .fill-high{background:var(--red)}
.c-medium{color:var(--orange)}   .fill-medium{background:var(--orange)}
.c-low{color:var(--blue)}        .fill-low{background:var(--blue)}
.c-info{color:var(--muted)}      .fill-info{background:var(--muted)}

/* ── Section chrome ──────────────────────────────────────── */
.section{margin-bottom:24px}
.section-hdr{
  font-size:13px;font-weight:600;color:var(--text);
  border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:14px;
}
.section-tag{
  font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);margin-bottom:10px;
}

/* ── Finding cards ───────────────────────────────────────── */
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:6px;margin-bottom:12px;overflow:hidden;
}
.card.sev-critical{border-left:4px solid var(--critical)}
.card.sev-high    {border-left:4px solid var(--red)}
.card.sev-medium  {border-left:4px solid var(--orange)}
.card.sev-low     {border-left:4px solid var(--blue)}
.card.sev-info    {border-left:4px solid var(--muted)}

.card-hdr{
  display:flex;align-items:center;gap:10px;padding:11px 16px;
  cursor:pointer;user-select:none;flex-wrap:wrap;
}
.card-hdr:hover{background:rgba(255,255,255,.025)}
.card-num{font-size:11px;color:var(--muted);min-width:22px}
.card-param{font-family:var(--mono);font-size:13px;font-weight:600;flex:1;min-width:60px}
.ctx-badge{
  display:inline-block;padding:1px 7px;border-radius:3px;
  font-size:10px;font-weight:600;letter-spacing:.03em;text-transform:uppercase;
  background:var(--surface2);color:var(--text);border:1px solid var(--border);
}
.sev-badge{
  display:inline-block;padding:2px 8px;border-radius:3px;
  font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
}
.sev-badge.sev-critical{background:var(--critical-d);color:var(--critical);border:1px solid var(--critical)}
.sev-badge.sev-high    {background:var(--red-d);color:var(--red);border:1px solid var(--red)}
.sev-badge.sev-medium  {background:var(--orange-d);color:var(--orange);border:1px solid var(--orange)}
.sev-badge.sev-low     {background:var(--blue-d);color:var(--blue);border:1px solid var(--blue)}
.sev-badge.sev-info    {background:rgba(125,133,144,.1);color:var(--muted);border:1px solid var(--border)}
.score-pill{font-size:11px;font-weight:600;color:var(--muted);white-space:nowrap}
.chevron{font-size:9px;color:var(--muted);transition:transform .2s;margin-left:auto}
.chevron.open{transform:rotate(90deg)}

.card-body{display:none;padding:0 16px 16px}
.card-body.open{display:block}

/* ── Detail table ────────────────────────────────────────── */
.dtbl{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
.dtbl td{padding:5px 8px;vertical-align:top;border-bottom:1px solid var(--border2)}
.dtbl tr:last-child td{border-bottom:none}
.dtbl td:first-child{
  color:var(--muted);white-space:nowrap;
  text-transform:uppercase;font-size:10px;letter-spacing:.06em;
  width:130px;padding-top:7px;
}
.dtbl td.v-mono{font-family:var(--mono);word-break:break-all}
.dtbl td.v-text{word-break:break-word}

/* ── Evidence box ────────────────────────────────────────── */
.evidence{
  background:var(--bg);border:1px solid var(--border);border-radius:4px;
  padding:8px 12px;margin-top:4px;font-size:11px;font-family:var(--mono);
  white-space:pre-wrap;word-break:break-all;max-height:110px;overflow-y:auto;
  color:var(--orange);
}

/* ── Encoding subsection ─────────────────────────────────── */
.enc-section{
  margin-top:10px;background:var(--surface2);
  border:1px solid var(--border2);border-radius:4px;overflow:hidden;
}
.enc-hdr{
  display:flex;align-items:center;justify-content:space-between;
  padding:7px 12px;cursor:pointer;user-select:none;
  font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);
}
.enc-hdr:hover{background:rgba(255,255,255,.02)}
.enc-chev{font-size:9px;transition:transform .2s}
.enc-chev.open{transform:rotate(90deg)}
.enc-body{display:none;padding:8px 12px 10px}
.enc-body.open{display:block}

.micro-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin-top:8px;margin-bottom:4px}
.micro-lbl:first-child{margin-top:0}
.tag-row{display:flex;flex-wrap:wrap;gap:4px}
.tag{
  display:inline-block;padding:1px 7px;border-radius:3px;
  font-size:11px;font-family:var(--mono);
  background:var(--surface);border:1px solid var(--border);color:var(--text);
}
.tag.t-enc  {background:var(--blue-d);border-color:var(--blue);color:var(--blue)}
.tag.t-pres {background:var(--red-d);border-color:var(--red);color:var(--red)}
.tag.t-enc-char{background:var(--orange-d);border-color:var(--orange);color:var(--orange)}

.diff-pill{
  display:inline-block;padding:2px 9px;border-radius:3px;
  font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
}
.diff-trivial {background:var(--critical-d);color:var(--critical)}
.diff-easy    {background:var(--red-d);color:var(--red)}
.diff-moderate{background:var(--orange-d);color:var(--orange)}
.diff-hard    {background:var(--blue-d);color:var(--blue)}
.diff-none    {background:rgba(125,133,144,.1);color:var(--muted)}

/* ── Notes ───────────────────────────────────────────────── */
.notes{font-size:12px;color:var(--text);line-height:1.55;word-break:break-word}

/* ── Clean banner ────────────────────────────────────────── */
.clean-banner{
  background:var(--green-d);border:1px solid var(--green);
  border-radius:6px;padding:24px;text-align:center;
  color:var(--green);font-size:15px;font-weight:600;
}

/* ── Metadata grid ───────────────────────────────────────── */
.meta-grid{
  background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:16px 20px;margin-top:20px;
}
.meta-items{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(220px,1fr));
  gap:14px;margin-top:12px;
}
.meta-item{display:flex;flex-direction:column;gap:2px}
.meta-item .m-lbl{font-size:10px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted)}
.meta-item .m-val{font-size:12px;color:var(--text);font-family:var(--mono);word-break:break-all}

/* ── Error list ──────────────────────────────────────────── */
.err-list{
  background:var(--surface);border:1px solid var(--border);
  border-radius:6px;padding:12px 16px;margin-top:20px;
}
.err-item{
  font-size:12px;font-family:var(--mono);color:var(--muted);
  padding:4px 0;border-bottom:1px solid var(--border2);
}
.err-item:last-child{border-bottom:none}

/* ── Footer ──────────────────────────────────────────────── */
.footer{
  margin-top:40px;text-align:center;font-size:11px;color:var(--muted);
  border-top:1px solid var(--border);padding-top:16px;
}

/* ── Print ───────────────────────────────────────────────── */
@media print{
  :root{
    --bg:#fff;--surface:#f6f8fa;--surface2:#edf0f2;
    --border:#d0d7de;--border2:#d0d7de;
    --text:#1f2328;--muted:#636c76;
    --red:#cf222e;--orange:#9a6700;--blue:#0969da;--green:#1a7f37;
    --critical:#cf222e;
  }
  body{font-size:12px}
  .card-hdr{cursor:default}
  .card-body,.enc-body{display:block!important}
  .chevron,.enc-chev{display:none}
  .page{padding:16px}
  .header{border-top-width:2px}
  .hdr-target{background:none;border:none;padding:0}
}
"""

_JS = """\
document.querySelectorAll('.card-hdr').forEach(h=>{
  h.addEventListener('click',()=>{
    h.nextElementSibling.classList.toggle('open');
    h.querySelector('.chevron').classList.toggle('open');
  });
});
document.querySelectorAll('.enc-hdr').forEach(h=>{
  h.addEventListener('click',e=>{
    e.stopPropagation();
    h.nextElementSibling.classList.toggle('open');
    const c=h.querySelector('.enc-chev');
    if(c)c.classList.toggle('open');
  });
});
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _e(s: object) -> str:
    return _html.escape(str(s), quote=True)


def _sev_cls(sev: str) -> str:
    s = sev.lower()
    return s if s in ("critical", "high", "medium", "low", "info") else "info"


def _diff_cls(diff: str) -> str:
    return _DIFFICULTY_CLASSES.get(diff.upper(), "none")


def _score_color(score: float) -> str:
    if score >= 9.0:
        return "c-critical"
    if score >= 7.0:
        return "c-red"
    if score >= 4.5:
        return "c-orange"
    if score >= 2.0:
        return "c-blue"
    return "c-green"


def _fmt_iso(iso: str) -> str:
    """Convert an ISO-8601 timestamp to a readable UTC string."""
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------


def _build_header(result: ModuleResult, n: int, session: dict) -> str:
    session_id   = session.get("session_id", "—")
    started_raw  = session.get("started_at", "")
    started      = _fmt_iso(started_raw) if started_raw else "—"
    duration     = session.get("duration_seconds")
    dur_str      = f"{duration:.3f}s" if isinstance(duration, (int, float)) else "—"
    verdict_cls  = "vuln" if n else "clean"
    verdict_txt  = "VULNERABLE" if n else "CLEAN"

    return f"""
<header class="header">
  <div>
    <div class="hdr-brand">XSS Framework</div>
    <div class="hdr-title">Reflective XSS Scan Report</div>
    <div class="hdr-sub">Professional Security Assessment</div>
    <div class="hdr-target">{_e(result.target)}</div>
  </div>
  <div class="hdr-right">
    <span class="verdict {verdict_cls}">{verdict_txt}</span>
    <div class="hdr-meta">
      <div class="hdr-meta-item">
        <span class="lbl">Session</span>
        <span class="val">{_e(session_id)}</span>
      </div>
      <div class="hdr-meta-item">
        <span class="lbl">Scan Started</span>
        <span class="val">{_e(started)}</span>
      </div>
      <div class="hdr-meta-item">
        <span class="lbl">Duration</span>
        <span class="val">{_e(dur_str)}</span>
      </div>
    </div>
  </div>
</header>"""


def _build_stats(result: ModuleResult, n: int, risk_score: float,
                 scores: list[float], session: dict) -> str:
    meta         = result.metadata
    payloads_t   = meta.get("payloads_tested", "—")
    params_t     = meta.get("parameters_tested", "—")
    duration     = session.get("duration_seconds")
    dur_str      = f"{duration:.2f}s" if isinstance(duration, (int, float)) else "—"
    error_n      = len(result.errors)

    vuln_cls   = "s-vuln" if n   else "s-clean"
    vuln_color = "c-red"  if n   else "c-green"
    err_color  = "c-orange" if error_n else ""
    rs_color   = _score_color(risk_score)

    return f"""
<div class="stats-row">
  <div class="stat-card {vuln_cls}">
    <div class="stat-value {vuln_color}">{n}</div>
    <div class="stat-label">Vulnerabilities</div>
  </div>
  <div class="stat-card">
    <div class="stat-value {rs_color}">{risk_score:.1f}</div>
    <div class="stat-label">Risk Score / 10</div>
  </div>
  <div class="stat-card">
    <div class="stat-value c-blue">{_e(str(payloads_t))}</div>
    <div class="stat-label">Payloads Tested</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{_e(str(params_t))}</div>
    <div class="stat-label">Parameters</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{_e(dur_str)}</div>
    <div class="stat-label">Duration</div>
  </div>
  <div class="stat-card">
    <div class="stat-value {err_color}">{error_n}</div>
    <div class="stat-label">Errors</div>
  </div>
</div>"""


def _build_sev_dist(sev_counts: dict[str, int], total: int) -> str:
    if total == 0:
        return ""

    rows = ""
    for sev, cls in (("CRITICAL", "critical"), ("HIGH", "high"),
                     ("MEDIUM", "medium"), ("LOW", "low")):
        cnt  = sev_counts.get(sev, 0)
        pct  = (cnt / total * 100) if total else 0
        rows += f"""
  <div class="sev-row">
    <span class="sev-lbl c-{cls}">{sev}</span>
    <div class="sev-track"><div class="sev-fill fill-{cls}" style="width:{pct:.1f}%"></div></div>
    <span class="sev-n">{cnt}</span>
  </div>"""

    return f"""
<div class="sev-dist">
  <div class="section-tag">Severity Distribution</div>
  {rows}
</div>"""


def _build_encoding_section(enc_types: list, chars_preserved: list,
                             difficulty: str) -> str:
    if not (enc_types or chars_preserved or difficulty):
        return ""

    enc_tags   = "".join(f'<span class="tag t-enc">{_e(t)}</span>' for t in enc_types) if enc_types else '<span class="tag">—</span>'
    pres_tags  = "".join(f'<span class="tag t-pres">{_e(c)}</span>' for c in chars_preserved) if chars_preserved else '<span class="tag">none</span>'
    diff_cls   = _diff_cls(difficulty)
    diff_pill  = f'<span class="diff-pill diff-{diff_cls}">{_e(difficulty)}</span>' if difficulty else "—"

    return f"""
<div class="enc-section">
  <div class="enc-hdr">
    Encoding Analysis
    <span class="enc-chev">&#9658;</span>
  </div>
  <div class="enc-body">
    <div class="micro-lbl">Encoding Types</div>
    <div class="tag-row">{enc_tags}</div>
    <div class="micro-lbl">Unencoded Dangerous Chars</div>
    <div class="tag-row">{pres_tags}</div>
    <div class="micro-lbl">Exploitation Difficulty</div>
    {diff_pill}
  </div>
</div>"""


def _build_finding_card(f: dict, idx: int) -> str:
    sev       = (f.get("severity") or "HIGH").upper()
    sev_cls   = _sev_cls(sev)
    param     = f.get("parameter", "")
    ctx       = f.get("reflection_context", "")
    payload   = f.get("payload", "")
    atk_url   = f.get("attack_url", "")
    evidence  = f.get("evidence", "")
    notes     = f.get("exploitation_notes", "")
    ftype     = f.get("type", "Reflected XSS")

    score     = f.get("severity_score")
    score_str = f"{score:.1f}" if isinstance(score, (int, float)) else "—"

    conf_val  = f.get("confidence", "")
    conf_lbl  = f.get("confidence_label", sev)

    enc_types  = f.get("encoding_types", [])
    chars_pres = f.get("dangerous_chars_preserved", [])
    difficulty = f.get("exploitation_difficulty", "")

    # Confidence display
    conf_disp = _e(conf_lbl)
    if isinstance(conf_val, int):
        conf_disp += f" ({conf_val}/4)"

    # Detail table
    rows  = f"<tr><td>Parameter</td><td class='v-mono'>{_e(param)}</td></tr>"
    rows += f"<tr><td>Type</td><td class='v-text'>{_e(ftype)}</td></tr>"
    rows += f"<tr><td>Context</td><td class='v-mono'>{_e(ctx)}</td></tr>"
    rows += f"<tr><td>Confidence</td><td class='v-text'>{conf_disp}</td></tr>"
    rows += f"<tr><td>Severity Score</td><td class='v-mono'>{_e(score_str)} / 10.0</td></tr>"
    rows += f"<tr><td>Attack URL</td><td class='v-mono'>{_e(atk_url)}</td></tr>"
    rows += f"<tr><td>Payload</td><td class='v-mono'>{_e(payload)}</td></tr>"
    if evidence:
        ev_short = evidence[:500] + ("…" if len(evidence) > 500 else "")
        rows += f"<tr><td>Evidence</td><td><div class='evidence'>{_e(ev_short)}</div></td></tr>"

    enc_html   = _build_encoding_section(enc_types, chars_pres, difficulty)
    notes_html = ""
    if notes:
        notes_html = f"""
<div style="margin-top:10px">
  <div class="micro-lbl">Exploitation Notes</div>
  <div class="notes">{_e(notes)}</div>
</div>"""

    open_body = " open" if idx == 1 else ""
    open_chev = " open" if idx == 1 else ""

    return f"""
<div class="card sev-{sev_cls}">
  <div class="card-hdr">
    <span class="card-num">#{idx}</span>
    <span class="card-param">{_e(param)}</span>
    <span class="ctx-badge">{_e(ctx)}</span>
    <span class="sev-badge sev-{sev_cls}">{_e(sev)}</span>
    <span class="score-pill">{_e(score_str)}&thinsp;/&thinsp;10</span>
    <span class="chevron{open_chev}">&#9658;</span>
  </div>
  <div class="card-body{open_body}">
    <table class="dtbl">{rows}</table>
    {enc_html}
    {notes_html}
  </div>
</div>"""


def _build_metadata(result: ModuleResult, session: dict,
                    generated: str) -> str:
    meta = result.metadata
    fv   = session.get("framework_version", _FRAMEWORK_VERSION)

    session_id  = session.get("session_id", "—")
    started_raw = session.get("started_at", "")
    finished_raw= session.get("finished_at", "")
    started     = _fmt_iso(started_raw)  if started_raw  else "—"
    finished    = _fmt_iso(finished_raw) if finished_raw else "—"
    duration    = session.get("duration_seconds")
    dur_str     = f"{duration:.3f}s" if isinstance(duration, (int, float)) else "—"

    items = [
        ("Framework",        f"XSS Framework v{_e(fv)}"),
        ("Module",           _e(result.module_name)),
        ("Session ID",       _e(session_id)),
        ("Started",          _e(started)),
        ("Finished",         _e(finished)),
        ("Duration",         _e(dur_str)),
        ("Payloads Loaded",  _e(str(meta.get("payloads_loaded", "—")))),
        ("Payloads Tested",  _e(str(meta.get("payloads_tested", "—")))),
        ("Parameters Tested",_e(str(meta.get("parameters_tested", "—")))),
        ("Report Generated", _e(generated)),
    ]
    cells = "".join(
        f'<div class="meta-item"><span class="m-lbl">{lbl}</span>'
        f'<span class="m-val">{val}</span></div>'
        for lbl, val in items
    )
    return f"""
<div class="meta-grid">
  <div class="section-tag">Scan Details</div>
  <div class="meta-items">{cells}</div>
</div>"""


def _build_errors(errors: list[str]) -> str:
    items = "".join(f'<div class="err-item">{_e(e)}</div>' for e in errors)
    n     = len(errors)
    return f"""
<div class="err-list">
  <div class="section-tag">{n} Request Error{"s" if n != 1 else ""}</div>
  {items}
</div>"""


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class HTMLReporter(BaseReporter):
    """
    Generates a self-contained dark-themed HTML scan report.

    The output is a single portable ``.html`` file with all CSS and JavaScript
    inlined — no external dependencies, suitable for sharing or PDF export.

    Args:
        output_file: Path to write the HTML.  ``None`` prints to stdout.
    """

    def __init__(self, output_file: Optional[str] = None) -> None:
        self._output_file = Path(output_file) if output_file else None

    def report(self, result: ModuleResult) -> None:
        html = self._render(result)
        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            self._output_file.write_text(html, encoding="utf-8")
        else:
            print(html)

    # ------------------------------------------------------------------

    def _render(self, result: ModuleResult) -> str:
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        findings  = result.findings
        n         = len(findings)
        session   = result.metadata.get("session", {})

        # Severity counts and risk score
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        scores: list[float] = []
        for f in findings:
            sev = (f.get("severity") or "HIGH").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            s = f.get("severity_score")
            if isinstance(s, (int, float)):
                scores.append(float(s))

        risk_score = max(scores) if scores else 0.0

        # Build sections
        header_html  = _build_header(result, n, session)
        stats_html   = _build_stats(result, n, risk_score, scores, session)
        sev_html     = _build_sev_dist(sev_counts, n) if n > 0 else ""

        if findings:
            cards = "".join(_build_finding_card(f, i) for i, f in enumerate(findings, 1))
            label = f'{n} Vulnerabilit{"ies" if n != 1 else "y"} Found'
            findings_html = f'<h2 class="section-hdr">{label}</h2>{cards}'
        else:
            findings_html = (
                '<h2 class="section-hdr">Findings</h2>'
                '<div class="clean-banner">&#10003;&ensp;No vulnerabilities detected.</div>'
            )

        meta_html   = _build_metadata(result, session, generated)
        errors_html = _build_errors(result.errors) if result.errors else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Report &mdash; {_e(result.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">
{header_html}
{stats_html}
{sev_html}
<div class="section">
{findings_html}
</div>
{meta_html}
{errors_html}
<footer class="footer">
  Generated by XSS Framework v{_FRAMEWORK_VERSION} &mdash; {_e(generated)}
</footer>
</div>
<script>{_JS}</script>
</body>
</html>"""
