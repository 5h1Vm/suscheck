"""Reporting engine for generating Markdown and Premium HTML security audits."""

import datetime
from typing import List
from suscheck.core.finding import ScanSummary, Finding, Severity, Verdict, ReportFormat

class ReportGenerator:
    """Generates security reports in various formats based on scan summaries."""

    @staticmethod
    def generate_markdown(summary: ScanSummary) -> str:
        """Generate a clean GitHub-flavored Markdown report."""
        lines = []
        lines.append(f"# SusCheck Security Audit: {summary.target}")
        lines.append(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Verdict:** {summary.verdict.value.upper()}")
        lines.append(f"**Platform Risk Index:** {summary.pri_score}/100")
        lines.append("")
        
        lines.append("## Executive Summary")
        lines.append(f"- **Artifact Type:** {summary.artifact_type}")
        lines.append(f"- **Scan Duration:** {summary.scan_duration:.2f}s")
        lines.append(f"- **Total Findings:** {summary.total_findings}")
        lines.append(f"- **Critical/High:** {summary.critical_count} / {summary.high_count}")
        lines.append("")

        lines.append("### Score Breakdown")
        import re
        tag_re = re.compile(r'\[/?(?:bold|red|yellow|green|blue|magenta|dim|cyan|white|black|yellow|orange|gray|grey|underline|italic|strike|inverse|link|/|)\]')
        
        for step in summary.pri_breakdown:
            # Clean up rich formatting tags for markdown
            clean_step = tag_re.sub('', step)
            lines.append(f"- {clean_step}")
        lines.append("")

        if summary.findings:
            lines.append("## Findings Detail")
            lines.append("| Severity | Finding | Module | Location |")
            lines.append("|----------|---------|--------|----------|")
            for f in summary.findings:
                loc = f"{f.file_path or 'N/A'}"
                if f.line_number:
                    loc += f":{f.line_number}"
                lines.append(f"| {f.severity.value.upper()} | {f.title} | {f.module} | {loc} |")
                
        return "\n".join(lines)

    @staticmethod
    def generate_html(summary: ScanSummary) -> str:
        """Generate a premium, modern dark-mode HTML report."""
        
        # Color mapping based on verdict
        verdict_colors = {
            Verdict.CLEAR: "#10b981",    # Emerald
            Verdict.CAUTION: "#eab308",  # Yellow
            Verdict.HOLD: "#f59e0b",     # Amber
            Verdict.ABORT: "#ef4444"     # Red
        }
        accent = verdict_colors.get(summary.verdict, "#6366f1")

        findings_html = ""
        for f in summary.findings:
            sev_class = f.severity.value.lower()
            loc = f"{f.file_path or 'N/A'}"
            if f.line_number:
                loc += f":{f.line_number}"
                
            ai_section = ""
            if f.ai_explanation:
                ai_section = f'''
                <div class="ai-box">
                    <strong>🤖 AI Analysis:</strong> {f.ai_explanation}
                </div>
                '''

            findings_html += f'''
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="badge {sev_class}">{f.severity.value.upper()}</span>
                    <span class="finding-id">{f.finding_id}</span>
                    <span class="module-tag">{f.module}</span>
                </div>
                <h3>{f.title}</h3>
                <p class="description">{f.description}</p>
                <div class="location">Location: <code>{loc}</code></div>
                {ai_section}
            </div>
            '''

        breakdown_html = ""
        import re
        tag_re = re.compile(r'\[/?(?:bold|red|yellow|green|blue|magenta|dim|cyan|white|black|yellow|orange|gray|grey|underline|italic|strike|inverse|link|/|)\]')
        
        for step in summary.pri_breakdown:
            # Clean up rich formatting tags for HTML
            clean_step = tag_re.sub('', step)
            # Re-apply some basic styling for logic
            if "total score" in clean_step.lower():
                clean_step = f"<strong>{clean_step}</strong>"
            breakdown_html += f"<li>{clean_step}</li>"

        html_template = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SusCheck Report: {summary.target}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --accent: {accent};
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #34d399;
            --info: #38bdf8;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 3rem;
            border-bottom: 2px solid var(--surface);
            padding-bottom: 1.5rem;
        }}
        h1 {{ margin: 0; font-weight: 800; font-size: 2.5rem; letter-spacing: -1px; }}
        .verdict-banner {{
            background: var(--surface);
            border-radius: 1rem;
            padding: 2rem;
            display: flex;
            align-items: center;
            gap: 2rem;
            margin-bottom: 3rem;
            border: 1px solid rgba(255,255,255,0.05);
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        .pri-gauge {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            border: 10px solid var(--surface-hover);
            border-top-color: var(--accent);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            flex-shrink: 0;
        }}
        .pri-value {{ font-size: 2.5rem; font-weight: 800; color: var(--accent); }}
        .pri-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-dim); }}
        
        .verdict-info h2 {{ margin: 0; font-size: 2rem; color: var(--accent); text-transform: uppercase; }}
        
        .grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
        }}
        .card {{
            background: var(--surface);
            border-radius: 1rem;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        .card h2 {{ margin-top: 0; font-size: 1.2rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 1px; }}
        
        ul.breakdown {{ list-style: none; padding: 0; }}
        ul.breakdown li {{ margin-bottom: 0.5rem; padding-left: 1.5rem; position: relative; }}
        ul.breakdown li::before {{ content: "•"; position: absolute; left: 0; color: var(--accent); }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }}
        .stat-item {{ background: var(--bg); padding: 1rem; border-radius: 0.5rem; text-align: center; }}
        .stat-val {{ display: block; font-size: 1.5rem; font-weight: 800; }}
        .stat-lbl {{ font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; }}

        .findings-list {{ margin-top: 3rem; }}
        .finding-card {{
            background: var(--surface);
            border-radius: 1rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border-left: 5px solid var(--accent);
            transition: transform 0.2s;
        }}
        .finding-card:hover {{ transform: translateY(-3px); background: var(--surface-hover); }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        
        .finding-header {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; align-items: center; }}
        .badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 2rem;
            font-size: 0.7rem;
            font-weight: 800;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); color: #000; }}
        .badge.low {{ background: var(--low); color: #000; }}
        
        .module-tag {{ color: var(--text-dim); font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; }}
        .description {{ color: var(--text-dim); }}
        .location {{ margin-top: 1rem; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; color: var(--accent); }}
        
        .ai-box {{
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(168, 85, 247, 0.1);
            border: 1px solid rgba(168, 85, 247, 0.3);
            border-radius: 0.5rem;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>SusCheck Scan</h1>
                <div style="color: var(--text-dim)">Target: {summary.target}</div>
            </div>
            <div style="text-align: right; color: var(--text-dim); font-size: 0.9rem;">
                Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                Duration: {summary.scan_duration:.2f}s
            </div>
        </header>

        <div class="verdict-banner">
            <div class="pri-gauge">
                <span class="pri-value">{summary.pri_score}</span>
                <span class="pri-label">PRI Score</span>
            </div>
            <div class="verdict-info">
                <h2>Verdict: {summary.verdict.value}</h2>
                <div style="margin-top: 0.5rem; opacity: 0.8;">
                    This artifact has been classified with a <strong>{summary.verdict.value.upper()}</strong> status after evaluating {summary.total_findings} security indicators.
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Mathematical Breakdown</h2>
                <ul class="breakdown">
                    {breakdown_html}
                </ul>
            </div>
            <div class="card">
                <h2>Findings Summary</h2>
                <div class="stats-grid">
                    <div class="stat-item"><span class="stat-val" style="color: var(--critical)">{summary.critical_count}</span><span class="stat-lbl">Critical</span></div>
                    <div class="stat-item"><span class="stat-val" style="color: var(--high)">{summary.high_count}</span><span class="stat-lbl">High</span></div>
                    <div class="stat-item"><span class="stat-val" style="color: var(--medium)">{summary.medium_count}</span><span class="stat-lbl">Medium</span></div>
                    <div class="stat-item"><span class="stat-val">{summary.info_count}</span><span class="stat-lbl">Info</span></div>
                </div>
                <div style="margin-top: 1.5rem; font-size: 0.9rem;">
                    <strong>Artifact:</strong> {summary.artifact_type}<br>
                    <strong>Trust Score:</strong> {f'{summary.trust_score:.1f}/10' if summary.trust_score is not None else 'N/A'}<br>
                    <strong>Modules:</strong> {', '.join(summary.modules_ran)}
                </div>
            </div>
        </div>

        <div class="findings-list">
            <h2>Detailed Inventory</h2>
            {findings_html}
        </div>
    </div>
</body>
</html>
        '''
        return html_template
