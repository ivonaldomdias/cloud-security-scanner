# 🔐 cloud-security-scanner

> Scanner de segurança multicloud para análise de Security Groups, versões de SOs e microsserviços desatualizados — com score de risco consolidado.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-FF9900?style=flat-square&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![OCI](https://img.shields.io/badge/OCI-F80000?style=flat-square&logo=oracle&logoColor=white)](https://oracle.com/cloud)
[![GCP](https://img.shields.io/badge/GCP-4285F4?style=flat-square&logo=googlecloud&logoColor=white)](https://cloud.google.com)
[![Security](https://img.shields.io/badge/CIS_Benchmarks-aligned-red?style=flat-square)](https://cisecurity.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## 🎯 Objetivo

Identificar e priorizar falhas de segurança em ambientes multicloud de forma automatizada, gerando um **score de risco** e um **relatório executivo** com findings categorizados por severidade.

### Escopo da v1.0

| Check | AWS | OCI | GCP |
|---|---|---|---|
| Security Groups / Firewall Rules — portas expostas ao mundo (0.0.0.0/0) | ✅ | ✅ | ✅ |
| Instâncias com SO desatualizado (EOL / sem suporte) | ✅ | ✅ | ✅ |
| Microsserviços com imagens de contêiner desatualizadas | ✅ (ECS/EKS) | ✅ (OKE) | ✅ (GKE) |
| Score de segurança consolidado por cloud e global | ✅ | ✅ | ✅ |
| Relatório HTML + JSON | ✅ | ✅ | ✅ |

> 🚀 **Roadmap v2.0:** IAM overpermissions, S3/bucket público, secrets expostos, CIS Benchmark completo, remediação automática via Terraform, integração com Security Hub / OCI VSS / GCP SCC.

---

## 🗂️ Estrutura do Repositório

```
cloud-security-scanner/
├── scanners/
│   ├── base.py                    # Interface base para todos os scanners
│   ├── aws/
│   │   ├── sg_scanner.py          # Security Groups com portas abertas
│   │   ├── os_scanner.py          # SOs desatualizados (EC2)
│   │   └── container_scanner.py   # Imagens ECS/EKS desatualizadas
│   ├── oci/
│   │   ├── sg_scanner.py          # Security Lists com portas abertas
│   │   └── os_scanner.py          # SOs desatualizados (Compute)
│   └── gcp/
│       ├── fw_scanner.py          # Firewall Rules com portas abertas
│       └── os_scanner.py          # SOs desatualizados (Compute Engine)
├── scoring/
│   └── risk_scorer.py             # Cálculo do score de segurança
├── reporter/
│   └── report_generator.py        # Geração de relatório HTML + JSON
├── main.py                        # Ponto de entrada CLI
├── tests/
│   ├── test_sg_scanner.py
│   ├── test_risk_scorer.py
│   └── test_report_generator.py
├── docs/
│   └── scoring-methodology.md     # Metodologia de scoring
├── .env.example
├── pyproject.toml
└── README.md
```

---

## ⚡ Quick Start

### Pré-requisitos

- Python 3.11+ e [Poetry](https://python-poetry.org/)
- Credenciais configuradas para as clouds que deseja escanear

### Instalação

```bash
git clone https://github.com/ivonaldomdias/cloud-security-scanner.git
cd cloud-security-scanner

poetry install
cp .env.example .env
# Edite .env com suas credenciais
```

### Uso

```bash
# Escanear todas as clouds configuradas
poetry run python main.py --clouds all

# Escanear apenas AWS, região us-east-1
poetry run python main.py --clouds aws --regions us-east-1

# Escanear AWS + GCP com relatório HTML
poetry run python main.py --clouds aws,gcp --output reports/ --format html

# Dry-run: exibe findings no terminal sem salvar
poetry run python main.py --clouds aws --dry-run
```

### Output de Exemplo

```
╔══════════════════════════════════════════════════════════╗
║        Cloud Security Scanner — v1.0                    ║
║        Ivonaldo Micheluti Dias | Cloud & FinOps         ║
╚══════════════════════════════════════════════════════════╝

Clouds escaneadas : AWS, GCP
Regiões           : us-east-1, us-east1
Findings totais   : 23
  🔴 CRITICAL     : 5
  🟠 HIGH         : 9
  🟡 MEDIUM       : 7
  🟢 LOW          : 2

Score de Segurança Global : 52 / 100  ⚠️  ALTO RISCO

Relatório salvo em: reports/security_report_20240115_143022.html
```

---

## 📊 Metodologia de Score

Veja [`docs/scoring-methodology.md`](docs/scoring-methodology.md) para a metodologia completa.

| Severidade | Peso | Exemplos |
|---|---|---|
| CRITICAL | -20 pts | SSH/RDP aberto para 0.0.0.0/0 |
| HIGH | -10 pts | SO sem suporte (EOL), porta DB exposta |
| MEDIUM | -5 pts | Porta não padrão exposta, imagem desatualizada |
| LOW | -2 pts | Porta de monitoramento exposta internamente |

Score inicia em **100** e é decrementado por finding. Score final por faixa:

| Faixa | Classificação |
|---|---|
| 80–100 | 🟢 Seguro |
| 60–79 | 🟡 Atenção |
| 40–59 | 🟠 Alto Risco |
| 0–39 | 🔴 Crítico |

---

## 🧪 Testes

```bash
poetry run pytest tests/ -v --cov=scanners --cov=scoring --cov=reporter --cov-report=term-missing
```

---

## 🗺️ Roadmap

### v1.0 (atual)
- [x] Security Groups / Firewall Rules expostos
- [x] SOs em EOL
- [x] Imagens de contêiner desatualizadas
- [x] Score de risco consolidado
- [x] Relatório HTML + JSON

### v2.0 (próxima release)
- [ ] IAM overpermissions (políticas com `*:*`)
- [ ] S3 / GCS / OCI Object Storage públicos
- [ ] Secrets Manager — segredos sem rotação
- [ ] CIS Benchmark completo (AWS, GCP, OCI)
- [ ] Integração com AWS Security Hub
- [ ] Integração com GCP Security Command Center
- [ ] Remediação automática via Terraform
- [ ] Notificações via Slack / Teams
- [ ] Agendamento via GitHub Actions / Databricks Job

---

## 📄 Licença

MIT License — veja [LICENSE](LICENSE) para detalhes.

---

<p align="center">
  Desenvolvido por <a href="https://www.linkedin.com/in/ivonaldo-micheluti-dias-61580470/">Ivonaldo Micheluti Dias</a> · Cloud & FinOps Engineer
</p>
