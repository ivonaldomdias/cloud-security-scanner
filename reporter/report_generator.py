"""Gerador de relatórios de segurança em HTML e JSON.

Produz um relatório executivo HTML com score visual, resumo por severidade,
tabela de findings e recomendações prioritizadas.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from scoring.risk_scorer import SecurityReport
from scanners.base import Severity

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "INFO":     "#6b7280",
}

SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}


def _score_color(score: int) -> str:
    if score >= 80: return "#16a34a"
    if score >= 60: return "#d97706"
    if score >= 40: return "#ea580c"
    return "#dc2626"


def export_json(report: SecurityReport, output_path: Path) -> None:
    """Exporta relatório em JSON estruturado."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    logger.info("JSON exportado: %s", output_path)


def export_html(report: SecurityReport, output_path: Path) -> None:
    """Exporta relatório executivo em HTML."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    score_color = _score_color(report.global_score)

    # Cards de severity summary
    severity_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = report.summary_by_severity.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        emoji = SEVERITY_EMOJIS[sev]
        severity_cards += f"""
        <div class="card" style="border-top: 4px solid {color}">
            <div class="card-label">{emoji} {sev}</div>
            <div class="card-value" style="color:{color}">{count}</div>
        </div>"""

    # Cloud score cards
    cloud_cards = ""
    for cs in report.cloud_scores:
        cc = _score_color(cs.score)
        cloud_cards += f"""
        <div class="card" style="border-top: 4px solid {cc}">
            <div class="card-label">☁️ {cs.cloud.upper()} · {cs.region}</div>
            <div class="card-value" style="color:{cc}">{cs.score}<span style="font-size:14px">/100</span></div>
            <div style="font-size:12px;color:#666;margin-top:4px">{cs.classification_emoji} {cs.classification} · {cs.total_findings} findings</div>
        </div>"""

    # Tabela de findings
    rows = ""
    for f in report.findings:
        color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
        emoji = SEVERITY_EMOJIS.get(f.severity.value, "⚪")
        rows += f"""
        <tr>
            <td><span style="color:{color};font-weight:bold">{emoji} {f.severity.value}</span></td>
            <td><code style="font-size:11px">{f.cloud.upper()} · {f.region}</code></td>
            <td>{f.resource_type}</td>
            <td><code style="font-size:11px">{f.resource_id}</code></td>
            <td>{f.title}</td>
            <td style="font-size:11px;color:#555;max-width:280px">{f.remediation[:120]}...</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Cloud Security Report — {report.scanned_at[:10]}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; color: #1e293b; }}
    .header {{ background: #1e293b; color: white; padding: 32px 40px; }}
    .header h1 {{ font-size: 24px; font-weight: 700; }}
    .header p {{ color: #94a3b8; font-size: 14px; margin-top: 6px; }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
    .section-title {{ font-size: 16px; font-weight: 700; color: #1e293b; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; text-transform: uppercase; letter-spacing: 1px; }}
    .score-block {{ display: flex; align-items: center; gap: 24px; background: white; border-radius: 12px; padding: 28px 36px; margin-bottom: 32px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .score-number {{ font-size: 72px; font-weight: 800; line-height: 1; color: {score_color}; }}
    .score-label {{ font-size: 18px; font-weight: 600; color: {score_color}; }}
    .score-meta {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
    .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }}
    .card {{ background: white; border-radius: 10px; padding: 18px 24px; min-width: 160px; box-shadow: 0 1px 4px rgba(0,0,0,.08); flex: 1; }}
    .card-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
    .card-value {{ font-size: 36px; font-weight: 800; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 32px; }}
    th {{ background: #1e293b; color: white; padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #f1f5f9; font-size: 13px; vertical-align: top; }}
    tr:hover td {{ background: #f8fafc; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; }}
    .footer {{ text-align: center; color: #94a3b8; font-size: 12px; padding: 24px; margin-top: 16px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🔐 Cloud Security Report</h1>
    <p>Gerado em: {report.scanned_at} · Clouds: {', '.join(c.upper() for c in report.clouds_scanned)} · Regiões: {', '.join(report.regions_scanned)}</p>
  </div>

  <div class="container">

    <div class="score-block">
      <div class="score-number">{report.global_score}</div>
      <div>
        <div class="score-label">{report.global_classification_emoji} {report.global_classification}</div>
        <div class="score-meta">Score global de segurança (0–100) · {len(report.findings)} findings totais</div>
        <div class="score-meta" style="margin-top:8px">Score base: 100 · Desconto total: {100 - report.global_score} pontos</div>
      </div>
    </div>

    <div class="section-title">Findings por Severidade</div>
    <div class="cards">{severity_cards}</div>

    <div class="section-title">Score por Cloud / Região</div>
    <div class="cards">{cloud_cards}</div>

    <div class="section-title">Findings Detalhados ({len(report.findings)} total)</div>
    <table>
      <thead>
        <tr>
          <th>Severidade</th><th>Cloud · Região</th><th>Tipo</th>
          <th>Resource ID</th><th>Título</th><th>Remediação (resumo)</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>

  </div>

  <div class="footer">
    Desenvolvido por <strong>Ivonaldo Micheluti Dias</strong> · Cloud & FinOps Engineer ·
    <a href="https://github.com/ivonaldomdias/cloud-security-scanner">github.com/ivonaldomdias</a>
  </div>
</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
    logger.info("HTML exportado: %s", output_path)


def generate_report(
    report: SecurityReport,
    output_dir: Path,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Gera relatório nos formatos solicitados.

    Args:
        report: SecurityReport consolidado.
        output_dir: Diretório de saída.
        formats: Lista de formatos ('html', 'json'). Padrão: ambos.

    Returns:
        Dicionário {formato: caminho_do_arquivo}.
    """
    if formats is None:
        formats = ["html", "json"]

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}

    if "json" in formats:
        json_path = output_dir / f"security_report_{timestamp}.json"
        export_json(report, json_path)
        outputs["json"] = json_path

    if "html" in formats:
        html_path = output_dir / f"security_report_{timestamp}.html"
        export_html(report, html_path)
        outputs["html"] = html_path

    return outputs
