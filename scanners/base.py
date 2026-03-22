"""Interface base e modelos de dados para todos os scanners de segurança.

Define o contrato que todos os scanners (AWS, OCI, GCP) devem implementar,
garantindo consistência nos findings e no pipeline de relatório.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Nível de severidade de um finding de segurança."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingCategory(str, Enum):
    """Categoria do finding."""
    NETWORK_EXPOSURE  = "NETWORK_EXPOSURE"   # Portas expostas ao mundo
    OUTDATED_OS       = "OUTDATED_OS"        # SO em EOL / sem suporte
    OUTDATED_IMAGE    = "OUTDATED_IMAGE"     # Imagem de contêiner desatualizada
    IAM               = "IAM"               # (v2.0) Overpermissions
    STORAGE           = "STORAGE"           # (v2.0) Bucket público
    SECRETS           = "SECRETS"           # (v2.0) Segredos expostos


# ── Portas críticas — exposição ao mundo = CRITICAL ───────────────────────────
CRITICAL_PORTS: dict[int, str] = {
    22:    "SSH",
    3389:  "RDP",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    2379:  "etcd",
    2380:  "etcd peer",
}

HIGH_PORTS: dict[int, str] = {
    21:    "FTP",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    111:   "RPC",
    137:   "NetBIOS",
    445:   "SMB",
    5900:  "VNC",
    8080:  "HTTP Alt",
    8443:  "HTTPS Alt",
}

# ── SOs em EOL (End of Life) ──────────────────────────────────────────────────
EOL_OS_PATTERNS: list[str] = [
    "ubuntu 14", "ubuntu 16", "ubuntu 18",
    "debian 8", "debian 9", "debian 10",
    "centos 6", "centos 7", "centos 8",
    "rhel 6", "rhel 7",
    "windows server 2008", "windows server 2012", "windows server 2016",
    "amazon linux 1", "amazon linux 2",   # amazon linux 2 EOL Jun/2025
    "oracle linux 6", "oracle linux 7",
]

# Padrões que indicam SO atual (não EOL)
CURRENT_OS_PATTERNS: list[str] = [
    "ubuntu 22", "ubuntu 24",
    "debian 11", "debian 12",
    "centos stream 9",
    "rhel 8", "rhel 9",
    "windows server 2019", "windows server 2022",
    "amazon linux 2023",
    "oracle linux 8", "oracle linux 9",
]


@dataclass
class Finding:
    """Representa uma falha de segurança identificada.

    Attributes:
        id: Identificador único (ex: AWS-SG-001).
        cloud: Provedor cloud (aws, oci, gcp).
        region: Região onde o recurso foi encontrado.
        resource_id: ID do recurso afetado.
        resource_name: Nome legível do recurso.
        resource_type: Tipo do recurso (security_group, instance, container...).
        category: Categoria do finding.
        severity: Nível de severidade.
        title: Título curto do finding.
        description: Descrição detalhada.
        remediation: Passos de remediação recomendados.
        cvss_score: Score CVSS estimado (0-10).
        tags: Tags do recurso afetado.
        raw_data: Dados brutos do recurso para auditoria.
        detected_at: Timestamp de detecção.
    """

    id: str
    cloud: str
    region: str
    resource_id: str
    resource_name: str
    resource_type: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    remediation: str
    cvss_score: float = 0.0
    tags: dict[str, str] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    @property
    def risk_weight(self) -> int:
        """Peso do finding para cálculo do score de segurança."""
        return {
            Severity.CRITICAL: 20,
            Severity.HIGH:     10,
            Severity.MEDIUM:    5,
            Severity.LOW:       2,
            Severity.INFO:      0,
        }[self.severity]

    def to_dict(self) -> dict[str, Any]:
        """Serializa o finding para dicionário."""
        return {
            "id":            self.id,
            "cloud":         self.cloud,
            "region":        self.region,
            "resource_id":   self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "category":      self.category.value,
            "severity":      self.severity.value,
            "title":         self.title,
            "description":   self.description,
            "remediation":   self.remediation,
            "cvss_score":    self.cvss_score,
            "tags":          self.tags,
            "detected_at":   self.detected_at,
        }


# ── Interface base ────────────────────────────────────────────────────────────
class BaseScanner(ABC):
    """Interface base que todos os scanners de cloud devem implementar.

    Args:
        region: Região a ser escaneada.
    """

    def __init__(self, region: str) -> None:
        self.region = region
        self._findings: list[Finding] = []

    @property
    def cloud(self) -> str:
        """Nome do provedor cloud (aws, oci, gcp)."""
        raise NotImplementedError

    @abstractmethod
    def scan_security_groups(self) -> list[Finding]:
        """Escaneia Security Groups / Firewall Rules por portas expostas."""
        ...

    @abstractmethod
    def scan_outdated_os(self) -> list[Finding]:
        """Escaneia instâncias com SOs em EOL ou sem suporte."""
        ...

    @abstractmethod
    def scan_outdated_containers(self) -> list[Finding]:
        """Escaneia contêineres/pods com imagens desatualizadas."""
        ...

    def run_all(self) -> list[Finding]:
        """Executa todos os scanners disponíveis.

        Returns:
            Lista consolidada de findings.
        """
        import logging
        logger = logging.getLogger(self.__class__.__name__)

        all_findings: list[Finding] = []

        for scan_fn, label in [
            (self.scan_security_groups,    "Security Groups"),
            (self.scan_outdated_os,        "Outdated OS"),
            (self.scan_outdated_containers,"Outdated Containers"),
        ]:
            logger.info("[%s] Executando: %s...", self.cloud.upper(), label)
            try:
                findings = scan_fn()
                all_findings.extend(findings)
                logger.info("[%s] %s → %d finding(s)", self.cloud.upper(), label, len(findings))
            except Exception as exc:
                logger.error("[%s] Erro em %s: %s", self.cloud.upper(), label, exc)

        self._findings = all_findings
        return all_findings
