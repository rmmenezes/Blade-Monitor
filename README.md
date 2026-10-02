# Blade Monitor

Monitor de **exposição externa** (EASM — *External Attack Surface Monitoring*).
Descobre periodicamente o que da sua organização está visível na internet,
avalia riscos e alerta quando algo **novo** aparece.

> ⚠️ Use apenas em domínios/IPs que você possui ou tem autorização formal para testar.

## Como funciona

```
domínios ──► Certificate Transparency (crt.sh) ──► subdomínios ─┐
IPs/CIDRs ──────────────────────────────────────────────────────┤
                                                                ▼
                                                  resolução DNS (hosts ativos)
                                                                ▼
                                        varredura TCP (connect) nas portas configuradas
                                                                ▼
                      enriquecimento: certificado TLS · HTTP (status, título, headers) · banner
                                                                ▼
                                        regras de risco ──► achados com severidade
                                                                ▼
                     snapshot no SQLite ──► diff com a execução anterior ──► relatório + webhook
```

### O que é detectado

| Regra | Severidade | Exemplo |
|---|---|---|
| `risky-port` | média → crítica | Redis, MongoDB, Elasticsearch, SMB, RDP, Telnet, bancos de dados, Docker API |
| `cert-expired` / `cert-expiring` | alta / média | certificado vencido ou vencendo em ≤ N dias |
| `cert-self-signed` / `cert-untrusted` | média | cadeia não confiável |
| `cert-hostname-mismatch` | média | certificado não cobre o hostname |
| `weak-tls` | média | TLS 1.0/1.1 negociado |
| `sensitive-panel` | média / alta | *Index of /*, phpMyAdmin, Jenkins, Grafana, Kibana, telas de login/admin |
| `http-no-redirect` | baixa | HTTP sem redirecionar para HTTPS |
| `server-version-disclosure` / `banner-version` | baixa | `nginx/1.18.0`, `OpenSSH_8.9p1` |
| `missing-security-headers` | info | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |

### Detecção de mudanças

Cada execução é salva como snapshot. O relatório e o alerta destacam:
novos hosts/subdomínios, novos serviços (portas abertas), serviços fechados,
novos achados e achados resolvidos.

## Uso

Requer Python ≥ 3.11, sem dependências externas.

```bash
cp config.example.toml config.toml   # edite os alvos
python -m blade_monitor scan         # executa uma varredura
python -m blade_monitor scan --interval 360   # modo contínuo (a cada 6h)
python -m blade_monitor history      # lista snapshots
python -m blade_monitor show [ID]    # exibe relatório de um snapshot
```

Ou instale: `pip install .` e use o comando `blade-monitor`.

Relatórios em JSON e Markdown são gravados em `reports/`. O código de saída
é `2` quando há achados de severidade alta ou crítica (útil em CI/cron).

Exemplo de agendamento via cron (diário, 6h):

```
0 6 * * * cd /opt/blade-monitor && python3 -m blade_monitor scan >> monitor.log 2>&1
```

### Alertas

Configure `alerts.webhook_url` com um *incoming webhook* do Slack, Mattermost
ou Teams. Só são enviados alertas para **mudanças** (novos hosts, serviços ou
achados com severidade ≥ `alerts.min_severity`).

## Testes

```bash
python -m unittest discover -s tests -v
```

Os testes de integração sobem servidores locais (HTTP, HTTPS autoassinado e
um serviço com banner SSH) e executam a varredura real contra eles.

## Estrutura

```
blade_monitor/
  config.py      # leitura do config.toml
  discovery.py   # CT logs (crt.sh), DNS, CIDR, exclusões
  scanner.py     # TCP connect, TLS, HTTP, banners
  rules.py       # regras de risco -> achados
  storage.py     # snapshots em SQLite
  diff.py        # comparação entre snapshots
  report.py      # relatórios Markdown/JSON e webhook
  cli.py         # comandos scan / history / show
```
