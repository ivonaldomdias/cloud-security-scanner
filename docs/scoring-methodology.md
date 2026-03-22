# 📊 Metodologia de Score de Segurança

## Visão Geral

O score de segurança é um indicador numérico de 0 a 100 que resume o nível de risco do ambiente cloud em um dado momento. Ele é calculado a partir dos findings identificados pelos scanners, com desconto proporcional à severidade de cada problema encontrado.

---

## Cálculo do Score

```
Score = 100 - Σ(peso × quantidade_de_findings_por_severidade)
Score mínimo = 0
```

### Tabela de Pesos por Severidade

| Severidade | Peso (desconto) | Exemplos |
|---|---|---|
| 🔴 CRITICAL | -20 pts | SSH (22) / RDP (3389) aberto para 0.0.0.0/0, protocolo all traffic aberto |
| 🟠 HIGH | -10 pts | SO em EOL, porta de banco de dados exposta (3306, 5432, 27017), runtime desatualizado |
| 🟡 MEDIUM | -5 pts | SO próximo do EOL, imagem com tag 'latest', porta HTTP alternativa exposta |
| 🟢 LOW | -2 pts | Configurações sub-ótimas sem risco imediato |
| ⚪ INFO | 0 pts | Informações relevantes sem impacto de segurança |

### Exemplo de Cálculo

```
Ambiente com os seguintes findings:
  - 2 Security Groups com SSH aberto (CRITICAL × 2) → -40 pts
  - 1 instância com SO em EOL (HIGH × 1)           → -10 pts
  - 3 contêineres com tag 'latest' (MEDIUM × 3)    → -15 pts

Score = 100 - 40 - 10 - 15 = 35 → 🔴 Crítico
```

---

## Classificação por Faixa

| Faixa | Classificação | Ação Recomendada |
|---|---|---|
| 80–100 | 🟢 Seguro | Manter monitoramento contínuo |
| 60–79 | 🟡 Atenção | Remediar findings HIGH em até 30 dias |
| 40–59 | 🟠 Alto Risco | Remediar findings CRITICAL em até 7 dias |
| 0–39 | 🔴 Crítico | Ação imediata — escalar para liderança |

---

## Critérios de Severidade

### CRITICAL
- Portas SSH (22) ou RDP (3389) abertas para 0.0.0.0/0
- Portas de banco de dados (MySQL, PostgreSQL, MongoDB, Redis) abertas para 0.0.0.0/0
- Regra de Security Group com protocolo `-1` (all traffic) para 0.0.0.0/0
- Acesso ao etcd (2379/2380) ou Elasticsearch (9200) expostos

### HIGH
- Sistema Operacional em EOL sem suporte de patches
- Runtime de contêiner desatualizado (Node.js 14, Python 3.7, Java 8)
- Porta FTP (21), Telnet (23) ou SMB (445) exposta
- Porta VNC (5900) exposta

### MEDIUM
- SO próximo do fim de suporte (< 6 meses)
- Imagem de contêiner com tag `latest` ou não imutável
- Portas HTTP alternativas (8080, 8443) expostas

### LOW
- Configurações sub-ótimas sem risco imediato
- Tags ausentes em recursos de segurança

---

## Roadmap — v2.0

Na próxima versão, os seguintes checks aumentarão a precisão do score:

- **IAM Overpermissions** (CRITICAL/HIGH): políticas com `"Action": "*"` e `"Resource": "*"`
- **Storage Público** (CRITICAL): S3, GCS ou OCI Object Storage com acesso público
- **Secrets sem Rotação** (HIGH): credenciais sem rotação há mais de 90 dias
- **CIS Benchmark** (todos os níveis): verificações baseadas nos benchmarks CIS para AWS, GCP e OCI

---

## Referências

- [CIS AWS Foundations Benchmark](https://cisecurity.org)
- [AWS Well-Architected — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [CVSS v3.1 Calculator](https://nvd.nist.gov/vuln-metrics/cvss)
