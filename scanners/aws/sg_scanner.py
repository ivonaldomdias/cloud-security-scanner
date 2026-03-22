"""Scanner de Security Groups da AWS — portas expostas para 0.0.0.0/0 ou ::/0.

Verifica todas as regras de entrada (ingress) de Security Groups em busca
de portas críticas acessíveis de qualquer origem na internet.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.base import (
    CRITICAL_PORTS, HIGH_PORTS,
    BaseScanner, Finding, FindingCategory, Severity,
)

logger = logging.getLogger(__name__)

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class AWSSGScanner(BaseScanner):
    """Escaneia Security Groups da AWS por portas expostas ao mundo."""

    cloud = "aws"

    def __init__(self, region: str) -> None:
        super().__init__(region)
        self._ec2 = boto3.client("ec2", region_name=region)

    def scan_security_groups(self) -> list[Finding]:
        """Escaneia todos os Security Groups da região."""
        findings: list[Finding] = []
        counter = 0

        try:
            paginator = self._ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    findings.extend(self._analyze_sg(sg, counter))
                    counter += 1

        except (BotoCoreError, ClientError) as exc:
            logger.error("Erro ao listar Security Groups em %s: %s", self.region, exc)

        return findings

    def _analyze_sg(self, sg: dict[str, Any], idx: int) -> list[Finding]:
        """Analisa as regras de um Security Group específico."""
        findings: list[Finding] = []
        sg_id   = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        tags    = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
        vpc_id  = sg.get("VpcId", "")

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort", 65535)
            protocol  = rule.get("IpProtocol", "-1")

            # Coletar CIDRs abertos
            open_cidrs = [
                r["CidrIp"] for r in rule.get("IpRanges", [])
                if r.get("CidrIp") in OPEN_CIDRS
            ] + [
                r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") in OPEN_CIDRS
            ]

            if not open_cidrs:
                continue

            # Protocolo -1 = all traffic
            if protocol == "-1":
                findings.append(Finding(
                    id=f"AWS-SG-{idx:04d}-ALLTRAFFIC",
                    cloud="aws",
                    region=self.region,
                    resource_id=sg_id,
                    resource_name=sg_name,
                    resource_type="security_group",
                    category=FindingCategory.NETWORK_EXPOSURE,
                    severity=Severity.CRITICAL,
                    title=f"Security Group permite TODO o tráfego de entrada de {open_cidrs}",
                    description=(
                        f"O Security Group '{sg_name}' ({sg_id}) na VPC {vpc_id} "
                        f"possui uma regra que permite todo o tráfego de entrada "
                        f"(protocolo: all) originado de {open_cidrs}. "
                        f"Isso expõe todas as portas do recurso associado à internet."
                    ),
                    remediation=(
                        "1. Remova a regra que permite todo o tráfego (0.0.0.0/0 com protocolo -1). "
                        "2. Adicione regras específicas apenas para as portas e protocolos necessários. "
                        "3. Restrinja a origem aos IPs ou Security Groups que realmente precisam de acesso. "
                        "4. Use AWS VPC Reachability Analyzer para validar o impacto antes de alterar."
                    ),
                    cvss_score=9.8,
                    tags=tags,
                    raw_data={"sg_id": sg_id, "vpc_id": vpc_id, "rule": rule},
                ))
                continue

            # Verificar porta a porta
            for port in range(from_port, min(to_port + 1, from_port + 1000)):
                if port in CRITICAL_PORTS:
                    service = CRITICAL_PORTS[port]
                    findings.append(Finding(
                        id=f"AWS-SG-{idx:04d}-{port}",
                        cloud="aws",
                        region=self.region,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        resource_type="security_group",
                        category=FindingCategory.NETWORK_EXPOSURE,
                        severity=Severity.CRITICAL,
                        title=f"Porta {port} ({service}) exposta para a internet em {sg_name}",
                        description=(
                            f"O Security Group '{sg_name}' ({sg_id}) permite acesso à porta {port} "
                            f"({service}) de qualquer origem ({open_cidrs}). "
                            f"Exposição de {service} à internet representa risco crítico de "
                            f"acesso não autorizado, força bruta e exploração de vulnerabilidades."
                        ),
                        remediation=(
                            f"1. Remova a regra de ingresso para porta {port} com origem 0.0.0.0/0. "
                            f"2. Restrinja o acesso ao {service} somente a IPs corporativos conhecidos ou via VPN. "
                            f"3. Se o acesso externo for necessário, use AWS Systems Manager Session Manager "
                            f"(SSH) ou RD Gateway (RDP) em vez de expor a porta diretamente. "
                            f"4. Habilite AWS GuardDuty para detectar tentativas de força bruta."
                        ),
                        cvss_score=9.8 if port in (22, 3389) else 8.6,
                        tags=tags,
                        raw_data={"sg_id": sg_id, "vpc_id": vpc_id, "port": port, "cidrs": open_cidrs},
                    ))

                elif port in HIGH_PORTS:
                    service = HIGH_PORTS[port]
                    findings.append(Finding(
                        id=f"AWS-SG-{idx:04d}-{port}",
                        cloud="aws",
                        region=self.region,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        resource_type="security_group",
                        category=FindingCategory.NETWORK_EXPOSURE,
                        severity=Severity.HIGH,
                        title=f"Porta {port} ({service}) exposta para a internet em {sg_name}",
                        description=(
                            f"O Security Group '{sg_name}' ({sg_id}) permite acesso à porta {port} "
                            f"({service}) de qualquer origem ({open_cidrs})."
                        ),
                        remediation=(
                            f"Restrinja o acesso à porta {port} ({service}) a IPs ou CIDRs específicos. "
                            f"Avalie se este serviço realmente precisa de acesso externo."
                        ),
                        cvss_score=7.5,
                        tags=tags,
                        raw_data={"sg_id": sg_id, "port": port, "cidrs": open_cidrs},
                    ))

        return findings

    def scan_outdated_os(self) -> list[Finding]:
        """Delegado ao OS scanner — retorna lista vazia aqui."""
        return []

    def scan_outdated_containers(self) -> list[Finding]:
        """Delegado ao container scanner — retorna lista vazia aqui."""
        return []
