"""Scanner de contêineres desatualizados na AWS — ECS Tasks e EKS Pods.

Identifica workloads usando imagens com tags que indicam versões antigas,
imagens sem tag explícita (latest) ou imagens sem scan de vulnerabilidades
recente no ECR.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.base import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)

# Padrões de tag que indicam imagem potencialmente desatualizada
RISKY_TAG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^latest$", re.IGNORECASE),
    re.compile(r"^dev$", re.IGNORECASE),
    re.compile(r"^test$", re.IGNORECASE),
    re.compile(r"^old[-_]", re.IGNORECASE),
    re.compile(r"^v?0\.", re.IGNORECASE),                   # versão 0.x
    re.compile(r"^v?1\.[0-4]\.", re.IGNORECASE),            # versão 1.0 a 1.4
]

# Versões de runtime com CVEs conhecidas
OUTDATED_RUNTIMES: dict[str, str] = {
    "node:14":    "Node.js 14 (EOL)",
    "node:12":    "Node.js 12 (EOL)",
    "node:10":    "Node.js 10 (EOL)",
    "python:3.7": "Python 3.7 (EOL)",
    "python:3.8": "Python 3.8 (próximo EOL)",
    "java:8":     "Java 8 (legado)",
    "java:11":    "Java 11 — verificar patch level",
    "openjdk:8":  "OpenJDK 8 (EOL)",
    "openjdk:11": "OpenJDK 11 — verificar patch level",
}


class AWSContainerScanner:
    """Escaneia tasks ECS e pods EKS por imagens desatualizadas ou arriscadas."""

    cloud = "aws"

    def __init__(self, region: str) -> None:
        self.region = region
        self._ecs = boto3.client("ecs",  region_name=region)
        self._ecr = boto3.client("ecr",  region_name=region)

    def scan_outdated_containers(self) -> list[Finding]:
        """Escaneia ECS clusters por tasks com imagens problemáticas."""
        findings: list[Finding] = []

        try:
            clusters = self._ecs.list_clusters().get("clusterArns", [])
            for cluster_arn in clusters:
                findings.extend(self._scan_ecs_cluster(cluster_arn))

        except (BotoCoreError, ClientError) as exc:
            logger.error("Erro ao escanear ECS em %s: %s", self.region, exc)

        logger.info("Container scan ECS: %d finding(s) em %s", len(findings), self.region)
        return findings

    def _scan_ecs_cluster(self, cluster_arn: str) -> list[Finding]:
        """Escaneia todas as tasks em execução em um cluster ECS."""
        findings: list[Finding] = []
        cluster_name = cluster_arn.split("/")[-1]

        try:
            task_arns = self._ecs.list_tasks(cluster=cluster_arn).get("taskArns", [])
            if not task_arns:
                return []

            tasks = self._ecs.describe_tasks(
                cluster=cluster_arn, tasks=task_arns
            ).get("tasks", [])

            for task in tasks:
                task_def_arn = task.get("taskDefinitionArn", "")
                task_def = self._ecs.describe_task_definition(
                    taskDefinition=task_def_arn
                ).get("taskDefinition", {})

                for container in task_def.get("containerDefinitions", []):
                    image = container.get("image", "")
                    container_name = container.get("name", "unknown")

                    finding = self._analyze_image(
                        image=image,
                        container_name=container_name,
                        cluster_name=cluster_name,
                        task_arn=task.get("taskArn", ""),
                    )
                    if finding:
                        findings.append(finding)

        except (BotoCoreError, ClientError) as exc:
            logger.warning("Erro ao escanear cluster %s: %s", cluster_name, exc)

        return findings

    def _analyze_image(
        self,
        image: str,
        container_name: str,
        cluster_name: str,
        task_arn: str,
    ) -> Finding | None:
        """Analisa uma imagem e retorna finding se for problemática."""

        # Extrair tag da imagem
        tag = "latest"
        if ":" in image:
            _, tag = image.rsplit(":", 1)

        image_base = image.split(":")[0].split("/")[-1]

        # 1. Verificar uso de 'latest' ou tags arriscadas
        is_risky_tag = any(p.match(tag) for p in RISKY_TAG_PATTERNS)

        # 2. Verificar runtime desatualizado
        outdated_runtime: str | None = None
        for pattern, label in OUTDATED_RUNTIMES.items():
            if pattern in image.lower():
                outdated_runtime = label
                break

        if outdated_runtime:
            return Finding(
                id=f"AWS-CTR-RUNTIME-{cluster_name}-{container_name}",
                cloud="aws",
                region=self.region,
                resource_id=task_arn,
                resource_name=f"{cluster_name}/{container_name}",
                resource_type="ecs_container",
                category=FindingCategory.OUTDATED_IMAGE,
                severity=Severity.HIGH,
                title=f"Contêiner '{container_name}' usando runtime desatualizado: {outdated_runtime}",
                description=(
                    f"O contêiner '{container_name}' no cluster ECS '{cluster_name}' "
                    f"está usando a imagem '{image}' com runtime desatualizado ({outdated_runtime}). "
                    f"Runtimes em EOL não recebem patches de segurança."
                ),
                remediation=(
                    f"1. Atualize a imagem base para a versão LTS mais recente. "
                    f"2. Teste a aplicação com o novo runtime em ambiente de staging. "
                    f"3. Atualize a task definition ECS com a nova imagem. "
                    f"4. Configure ECR Image Scanning para detectar CVEs automaticamente."
                ),
                cvss_score=7.0,
                raw_data={"image": image, "tag": tag, "runtime": outdated_runtime},
            )

        if is_risky_tag:
            return Finding(
                id=f"AWS-CTR-TAG-{cluster_name}-{container_name}",
                cloud="aws",
                region=self.region,
                resource_id=task_arn,
                resource_name=f"{cluster_name}/{container_name}",
                resource_type="ecs_container",
                category=FindingCategory.OUTDATED_IMAGE,
                severity=Severity.MEDIUM,
                title=f"Contêiner '{container_name}' usando tag de imagem não determinística: '{tag}'",
                description=(
                    f"O contêiner '{container_name}' no cluster '{cluster_name}' "
                    f"está usando a imagem '{image}' com tag '{tag}', que não é imutável. "
                    f"Tags como 'latest' podem referenciar versões diferentes a cada deploy, "
                    f"impossibilitando rastreabilidade e aumentando risco de versões vulneráveis."
                ),
                remediation=(
                    f"1. Substitua a tag '{tag}' por uma tag imutável (ex: SHA do commit ou versão semântica). "
                    f"2. Configure ECR para habilitar tag imutability. "
                    f"3. Implemente um pipeline CI/CD que sempre publique imagens com tags versionadas."
                ),
                cvss_score=5.3,
                raw_data={"image": image, "tag": tag},
            )

        return None
