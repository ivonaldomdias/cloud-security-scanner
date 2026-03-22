"""Ponto de entrada CLI do Cloud Security Scanner.

Uso:
    poetry run python main.py --clouds all
    poetry run python main.py --clouds aws --regions us-east-1
    poetry run python main.py --clouds aws,gcp --output reports/ --format html
    poetry run python main.py --clouds aws --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from scanners.aws.sg_scanner import AWSSGScanner
from scanners.aws.os_scanner import AWSOSScanner
from scanners.aws.container_scanner import AWSContainerScanner
from scanners.base import Finding
from scoring.risk_scorer import build_report
from reporter.report_generator import generate_report

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        🔐 Cloud Security Scanner — v1.0                 ║
║        Ivonaldo Micheluti Dias | Cloud & FinOps         ║
╚══════════════════════════════════════════════════════════╝
"""

DEFAULT_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1"],
    "oci": ["sa-saopaulo-1"],
    "gcp": ["us-east1"],
}


def run_aws_scan(regions: list[str]) -> list[Finding]:
    """Executa todos os scanners AWS nas regiões especificadas."""
    findings: list[Finding] = []

    for region in regions:
        logger.info("Escaneando AWS — região: %s", region)

        # Security Groups
        sg_scanner = AWSSGScanner(region=region)
        findings.extend(sg_scanner.scan_security_groups())

        # OS Desatualizado
        os_scanner = AWSOSScanner(region=region)
        findings.extend(os_scanner.scan_outdated_os())

        # Contêineres
        container_scanner = AWSContainerScanner(region=region)
        findings.extend(container_scanner.scan_outdated_containers())

    return findings


def print_summary(report: "SecurityReport") -> None:  # type: ignore[name-defined]
    """Exibe sumário no terminal."""
    from scoring.risk_scorer import SecurityReport
    print(BANNER)
    print(f"  Clouds escaneadas : {', '.join(c.upper() for c in report.clouds_scanned)}")
    print(f"  Regiões           : {', '.join(report.regions_scanned)}")
    print(f"  Findings totais   : {len(report.findings)}")
    print(f"    🔴 CRITICAL     : {report.summary_by_severity.get('CRITICAL', 0)}")
    print(f"    🟠 HIGH         : {report.summary_by_severity.get('HIGH', 0)}")
    print(f"    🟡 MEDIUM       : {report.summary_by_severity.get('MEDIUM', 0)}")
    print(f"    🟢 LOW          : {report.summary_by_severity.get('LOW', 0)}")
    print()
    print(f"  Score de Segurança Global : {report.global_score} / 100  "
          f"{report.global_classification_emoji} {report.global_classification}")
    print()

    if report.critical_findings:
        print("  ⚠️  Findings CRÍTICOS (ação imediata necessária):")
        for f in report.critical_findings[:5]:
            print(f"    • [{f.cloud.upper()} · {f.region}] {f.title}")
        if len(report.critical_findings) > 5:
            print(f"    ... e mais {len(report.critical_findings) - 5} finding(s) crítico(s)")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cloud Security Scanner — análise de falhas de segurança multicloud",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--clouds", default="aws",
        help="Clouds a escanear: aws, oci, gcp, ou 'all' (padrão: aws)"
    )
    parser.add_argument(
        "--regions", default=None,
        help="Regiões separadas por vírgula (padrão: us-east-1 para AWS)"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("reports"),
        help="Diretório de saída para os relatórios (padrão: reports/)"
    )
    parser.add_argument(
        "--format", choices=["html", "json", "both"], default="both",
        help="Formato do relatório (padrão: both)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Exibe findings no terminal sem salvar relatório"
    )
    args = parser.parse_args()

    scanned_at = datetime.utcnow().isoformat()
    clouds_requested = (
        list(DEFAULT_REGIONS.keys())
        if args.clouds == "all"
        else [c.strip() for c in args.clouds.split(",")]
    )

    all_findings: list[Finding] = []
    all_regions: list[str] = []

    for cloud in clouds_requested:
        regions = (
            [r.strip() for r in args.regions.split(",")]
            if args.regions
            else DEFAULT_REGIONS.get(cloud, [])
        )
        all_regions.extend(regions)

        if cloud == "aws":
            all_findings.extend(run_aws_scan(regions))
        elif cloud in ("oci", "gcp"):
            logger.info("Scanner para %s em desenvolvimento — v1.1", cloud.upper())

    # Construir relatório
    report = build_report(
        all_findings=all_findings,
        scanned_at=scanned_at,
        clouds=clouds_requested,
        regions=list(set(all_regions)),
    )

    print_summary(report)

    if not args.dry_run:
        formats = ["html", "json"] if args.format == "both" else [args.format]
        outputs = generate_report(report, args.output, formats)
        for fmt, path in outputs.items():
            print(f"  Relatório {fmt.upper()} salvo em: {path}")
    else:
        logger.info("[DRY-RUN] Relatório não salvo.")


if __name__ == "__main__":
    main()
