"""Cálculo do score de segurança baseado nos findings coletados.

Implementa a metodologia de scoring descrita em docs/scoring-methodology.md:
- Score base: 100
- Cada finding desconta pontos proporcionais à sua severidade
- Score mínimo: 0
- Classificação por faixa: Seguro / Atenção / Alto Risco / Crítico
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanners.base import Finding, Severity


# Peso de desconto por severidade
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH:     10,
    Severity.MEDIUM:    5,
    Severity.LOW:       2,
    Severity.INFO:      0,
}


@dataclass
class CloudScore:
    """Score de segurança de um provedor cloud específico."""

    cloud: str
    region: str
    score: int
    total_findings: int
    by_severity: dict[str, int]
    classification: str
    classification_emoji: str


@dataclass
class SecurityReport:
    """Relatório consolidado com scores e findings de todas as clouds."""

    scanned_at: str
    clouds_scanned: list[str]
    regions_scanned: list[str]
    global_score: int
    global_classification: str
    global_classification_emoji: str
    cloud_scores: list[CloudScore]
    findings: list[Finding]
    summary_by_severity: dict[str, int] = field(default_factory=dict)
    summary_by_category: dict[str, int] = field(default_factory=dict)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_at":               self.scanned_at,
            "clouds_scanned":           self.clouds_scanned,
            "regions_scanned":          self.regions_scanned,
            "global_score":             self.global_score,
            "global_classification":    self.global_classification,
            "cloud_scores": [
                {
                    "cloud":                 cs.cloud,
                    "region":               cs.region,
                    "score":                cs.score,
                    "total_findings":       cs.total_findings,
                    "by_severity":          cs.by_severity,
                    "classification":       cs.classification,
                }
                for cs in self.cloud_scores
            ],
            "summary_by_severity":  self.summary_by_severity,
            "summary_by_category":  self.summary_by_category,
            "total_findings":       len(self.findings),
            "findings":             [f.to_dict() for f in self.findings],
        }


def _classify_score(score: int) -> tuple[str, str]:
    """Retorna (classificação, emoji) para um score."""
    if score >= 80:
        return "Seguro",     "🟢"
    elif score >= 60:
        return "Atenção",    "🟡"
    elif score >= 40:
        return "Alto Risco", "🟠"
    else:
        return "Crítico",    "🔴"


def calculate_score(findings: list[Finding], base: int = 100) -> int:
    """Calcula o score de segurança a partir de uma lista de findings.

    Args:
        findings: Lista de findings coletados.
        base: Score base (padrão: 100).

    Returns:
        Score final entre 0 e 100.
    """
    total_deduction = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return max(0, base - total_deduction)


def build_report(
    all_findings: list[Finding],
    scanned_at: str,
    clouds: list[str],
    regions: list[str],
) -> SecurityReport:
    """Constrói o relatório consolidado de segurança.

    Args:
        all_findings: Lista completa de findings de todas as clouds.
        scanned_at: Timestamp do scan.
        clouds: Lista de clouds escaneadas.
        regions: Lista de regiões escaneadas.

    Returns:
        SecurityReport com scores globais e por cloud.
    """
    # Score global
    global_score = calculate_score(all_findings)
    global_class, global_emoji = _classify_score(global_score)

    # Sumário por severidade
    summary_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in all_findings:
        summary_severity[f.severity.value] += 1

    # Sumário por categoria
    summary_category: dict[str, int] = {}
    for f in all_findings:
        cat = f.category.value
        summary_category[cat] = summary_category.get(cat, 0) + 1

    # Scores por cloud/região
    cloud_scores: list[CloudScore] = []
    cloud_region_keys = {(f.cloud, f.region) for f in all_findings}

    for cloud, region in sorted(cloud_region_keys):
        cr_findings = [f for f in all_findings if f.cloud == cloud and f.region == region]
        cr_score = calculate_score(cr_findings)
        cr_class, cr_emoji = _classify_score(cr_score)

        by_sev: dict[str, int] = {s.value: 0 for s in Severity}
        for f in cr_findings:
            by_sev[f.severity.value] += 1

        cloud_scores.append(CloudScore(
            cloud=cloud,
            region=region,
            score=cr_score,
            total_findings=len(cr_findings),
            by_severity=by_sev,
            classification=cr_class,
            classification_emoji=cr_emoji,
        ))

    return SecurityReport(
        scanned_at=scanned_at,
        clouds_scanned=clouds,
        regions_scanned=regions,
        global_score=global_score,
        global_classification=global_class,
        global_classification_emoji=global_emoji,
        cloud_scores=cloud_scores,
        findings=sorted(
            all_findings,
            key=lambda f: list(Severity).index(f.severity)
        ),
        summary_by_severity=summary_severity,
        summary_by_category=summary_category,
    )
