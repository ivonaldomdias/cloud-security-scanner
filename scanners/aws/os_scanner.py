"""Scanner de SOs desatualizados em instâncias EC2 da AWS.

Verifica instâncias EC2 em execução cujo sistema operacional está em
End of Life (EOL) ou próximo do fim de suporte, representando risco
de vulnerabilidades não corrigidas.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.base import (
    EOL_OS_PATTERNS, Finding, FindingCategory, Severity,
)

logger = logging.getLogger(__name__)


# SOs próximos do EOL (HIGH em vez de CRITICAL)
NEAR_EOL_PATTERNS: list[str] = [
    "amazon linux 2",   # EOL Jun/2025
    "ubuntu 20",        # EOL Apr/2025
    "rhel 7",           # EOL Jun/2024
    "centos stream 8",  # EOL May/2024
]


class AWSOSScanner:
    """Escaneia instâncias EC2 com SOs em EOL ou próximos do fim de suporte."""

    cloud = "aws"

    def __init__(self, region: str) -> None:
        self.region = region
        self._ec2 = boto3.client("ec2", region_name=region)

    def scan_outdated_os(self) -> list[Finding]:
        """Escaneia todas as instâncias EC2 running por SO desatualizado."""
        findings: list[Finding] = []

        try:
            paginator = self._ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        finding = self._analyze_instance(instance)
                        if finding:
                            findings.append(finding)

        except (BotoCoreError, ClientError) as exc:
            logger.error("Erro ao listar instâncias EC2 em %s: %s", self.region, exc)

        logger.info("OS scan EC2: %d finding(s) em %s", len(findings), self.region)
        return findings

    def _get_os_from_instance(self, instance: dict[str, Any]) -> str:
        """Extrai informação de SO a partir dos dados da instância.

        Tenta em ordem: tag 'OS', tag 'os', Platform, nome da AMI.
        """
        tags = {t["Key"].lower(): t["Value"].lower() for t in instance.get("Tags", [])}

        # 1. Tag explícita de SO (melhor fonte)
        for key in ("os", "operating_system", "platform"):
            if key in tags:
                return tags[key]

        # 2. Campo Platform (geralmente só preenchido para Windows)
        platform = instance.get("Platform", "")
        if platform:
            return platform.lower()

        # 3. Nome da AMI (fonte menos confiável, mas útil)
        image_id = instance.get("ImageId", "")
        if image_id:
            try:
                images = self._ec2.describe_images(ImageIds=[image_id])
                images_list = images.get("Images", [])
                if images_list:
                    return images_list[0].get("Name", "").lower()
            except (BotoCoreError, ClientError):
                pass

        return ""

    def _analyze_instance(self, instance: dict[str, Any]) -> Finding | None:
        """Analisa uma instância EC2 e retorna finding se SO estiver desatualizado."""
        iid     = instance["InstanceId"]
        itype   = instance.get("InstanceType", "unknown")
        tags    = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        name    = tags.get("Name", iid)
        os_info = self._get_os_from_instance(instance)

        if not os_info:
            return None

        # Verificar EOL
        is_eol = any(pattern in os_info for pattern in EOL_OS_PATTERNS)
        is_near_eol = any(pattern in os_info for pattern in NEAR_EOL_PATTERNS)

        if is_eol:
            return Finding(
                id=f"AWS-OS-EOL-{iid}",
                cloud="aws",
                region=self.region,
                resource_id=iid,
                resource_name=name,
                resource_type="ec2_instance",
                category=FindingCategory.OUTDATED_OS,
                severity=Severity.HIGH,
                title=f"Instância EC2 '{name}' executando SO em EOL: {os_info}",
                description=(
                    f"A instância EC2 '{name}' ({iid}, tipo: {itype}) está executando "
                    f"'{os_info}', um sistema operacional que atingiu o End of Life (EOL) "
                    f"e não recebe mais patches de segurança. Isso expõe a instância a "
                    f"vulnerabilidades conhecidas sem possibilidade de correção oficial."
                ),
                remediation=(
                    f"1. Crie uma AMI de backup da instância '{name}' antes de qualquer mudança. "
                    f"2. Provisione uma nova instância com a versão LTS mais recente do SO. "
                    f"3. Migre as workloads e valide o funcionamento na nova instância. "
                    f"4. Descomissione a instância com SO em EOL após validação completa. "
                    f"5. Implemente AWS Systems Manager Patch Manager para automação futura."
                ),
                cvss_score=7.5,
                tags=tags,
                raw_data={"instance_id": iid, "instance_type": itype, "os_info": os_info},
            )

        if is_near_eol and not is_eol:
            return Finding(
                id=f"AWS-OS-NEAREOL-{iid}",
                cloud="aws",
                region=self.region,
                resource_id=iid,
                resource_name=name,
                resource_type="ec2_instance",
                category=FindingCategory.OUTDATED_OS,
                severity=Severity.MEDIUM,
                title=f"Instância EC2 '{name}' com SO próximo do EOL: {os_info}",
                description=(
                    f"A instância EC2 '{name}' ({iid}) está executando '{os_info}', "
                    f"que está próxima do fim de suporte. Planeje a migração antes do EOL."
                ),
                remediation=(
                    f"Planeje a migração para a versão LTS mais recente antes do fim de suporte de '{os_info}'. "
                    f"Use AWS Migration Hub para rastrear o progresso."
                ),
                cvss_score=5.0,
                tags=tags,
                raw_data={"instance_id": iid, "os_info": os_info},
            )

        return None
