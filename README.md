# Blade Monitor

Gestão de **superfície de ataque externa** (EASM — *External Attack Surface Management*).
Descobre periodicamente o que uma organização expõe na internet, avalia riscos,
atribui uma nota de segurança (A–F) e alerta quando algo **novo** aparece.

Dois modos de uso:

- **CLI** (`blade-monitor`) — um alvo, configuração em TOML, ideal para cron/CI.
- **Plataforma** (`blade-platform`) — SaaS multi-tenant com API REST, painel web,
  avaliação de fornecedores e **programa de parceiros para consultorias/MSSPs**.
  Veja [Plataforma](#plataforma).

🌐 **Página do projeto:** https://rmmenezes.github.io/Blade-Monitor/

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

## Página web

A pasta `docs/` contém a página pública do projeto, publicada no GitHub Pages
a cada push na `main`. Ela inclui um visualizador que abre os arquivos
`reports/snapshot-*.json` direto no navegador, sem enviar nada para servidor.
Resultados reais de varredura não são publicados.

## Plataforma

Plataforma multi-tenant inspirada em produtos de *security ratings*, gestão de
risco de terceiros e varredura contínua. Como o resto do projeto, usa só a
biblioteca padrão do Python (SQLite, `http.server`); o painel é JS puro.

### Início rápido

```bash
python -m blade_monitor.platform demo        # dados sintéticos (domínios *.example)
python -m blade_monitor.platform serve       # http://127.0.0.1:8080
```

Usuários de demonstração (senha `demo-password-123`): `admin@demo.example`,
`parceiro@demo.example`, `analista@demo.example`, `cliente@demo.example`.

Em produção:

```bash
BLADE_ADMIN_PASSWORD=... blade-platform --db /var/lib/blade/platform.db init --email voce@empresa.com
blade-platform --db /var/lib/blade/platform.db serve --host 127.0.0.1 --port 8080 --secure-cookies
# opcional: worker separado do servidor web
blade-platform --db /var/lib/blade/platform.db serve --no-worker --secure-cookies
blade-platform --db /var/lib/blade/platform.db worker
```

Publique atrás de um proxy reverso com HTTPS (nginx, Caddy) e use `--secure-cookies`.

### Publicação automática

A cada push na `main`, o workflow [`release`](.github/workflows/release.yml):

1. roda os testes;
2. publica a imagem Docker em `ghcr.io/rmmenezes/blade-monitor` (tags `latest`,
   versão e `sha-…`);
3. se a versão do `pyproject.toml` ainda não tiver tag, cria a tag `vX.Y.Z` e o
   GitHub Release com os pacotes Python. **Para lançar uma versão, basta subir o
   número da versão.**

A página do projeto (`docs/`) é publicada no GitHub Pages pelo workflow `pages`.

O container se configura só com variáveis de ambiente:

| Variável | Efeito |
|---|---|
| `BLADE_ADMIN_EMAIL` / `BLADE_ADMIN_PASSWORD` | cria o administrador no primeiro boot (se não houver nenhum) |
| `BLADE_SECURE_COOKIES=1` | cookies `Secure` (use atrás de HTTPS) |
| `BLADE_DEMO=1` | carrega os dados de demonstração num banco vazio |
| `PORT` | porta HTTP (padrão 8080) |
| `BLADE_DB` | caminho do SQLite (padrão `/data/platform.db`, volume persistente) |

**Servidor próprio com HTTPS automático** (Caddy + Let's Encrypt):

```bash
cat > .env <<EOT
DOMAIN=easm.suaempresa.com
BLADE_ADMIN_EMAIL=voce@suaempresa.com
BLADE_ADMIN_PASSWORD=troque-esta-senha
EOT
docker compose up -d
```

**Render (um clique, redeploy automático a cada push):**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/rmmenezes/Blade-Monitor)

**Só o container:**

```bash
docker run -d -p 8080:8080 -v blade-data:/data \
  -e BLADE_ADMIN_EMAIL=voce@suaempresa.com -e BLADE_ADMIN_PASSWORD=troque-esta-senha \
  ghcr.io/rmmenezes/blade-monitor:latest
```

### Funcionalidades

| Área | O que faz |
|---|---|
| **Nota de segurança** | 0–100 e conceito A–F por categoria (rede, TLS, web, vazamento de informação), normalizada pelo tamanho da superfície, com tendência histórica |
| **Ciclo de vida dos achados** | `open → resolved` automaticamente quando some na varredura seguinte; reabre se voltar; `accepted`/`false_positive` exigem justificativa e saem da nota |
| **Verificação de posse** | Varredura ativa só em ativos verificados: domínio por DNS TXT (`_blade-monitor.<domínio>`) ou arquivo `/.well-known/blade-monitor-verification.txt`; IP/CIDR por atestado (contrato/carta) registrado na auditoria |
| **Risco de terceiros** | Fornecedores avaliados em modo **passivo** (CT logs, DNS, uma requisição HTTP/HTTPS por host — sem varredura de portas e sem exigir autorização) |
| **Agendamento** | Fila no SQLite; frequência pelo plano (semanal, diária ou a cada 6h); reavaliação semanal de fornecedores |
| **Alertas** | Webhook por cliente (Slack/Teams/Mattermost) com severidade mínima, só para mudanças |
| **Relatório executivo** | HTML imprimível em PDF com a marca do parceiro (`/reports/scan/<id>`) |
| **API REST** | `/api/v1/*` com sessão (cookie + CSRF) ou chave de API (`Authorization: Bearer bm_...`) |
| **Auditoria** | Login, verificação/atestado de ativos, mudanças de status de achados, usuários etc. |

### Papéis

| Papel | Escopo |
|---|---|
| `admin` | Plataforma inteira; aprova parceiros e define níveis negociados |
| `partner_admin` | Todos os clientes do parceiro, marca, extrato e equipe |
| `partner_analyst` | Todos os clientes do parceiro (operação: ativos, varreduras, achados) |
| `org_admin` | A própria organização, inclusive usuários e alertas |
| `org_viewer` | Somente leitura da própria organização |

O isolamento entre tenants é verificado em cada rota: recursos de outro tenant
respondem `404`.

### Programa de parceiros

Para consultorias e MSSPs (`#/apply` no painel → aprovação pelo admin):

- **Revenda gerenciada.** O parceiro cadastra clientes no seu portfólio, paga o
  preço de atacado e define o preço final.
- **Indicação.** Clientes diretos que se cadastram com o código do parceiro
  (`#/signup?ref=BM-XXXX`) geram **20% de comissão recorrente**.
- **Pré-venda.** Avaliação passiva de prospects, com relatório na marca do parceiro.
- **Extrato mensal** com atacado, margem de revenda, comissões e líquido.

| Nível | Clientes gerenciados | Desconto/margem | White-label | Prospects/mês |
|---|---|---|---|---|
| Registered | 0+ | 10% | co-branded | 5 |
| Silver | 5+ | 20% | ✔ | 20 |
| Gold | 15+ | 30% | ✔ | 50 |
| Platinum | 40+ | 40% | ✔ | ilimitado |

Planos (preço de lista mensal, em USD): Essentials 149 (5 ativos, varredura
semanal), Professional 499 (25 ativos, diária), Enterprise 1.499 (200 ativos, a
cada 6h). Valores e níveis ficam em `blade_monitor/platform/partners.py`.

### Modelo de nota

Cada achado pesa conforme a severidade (crítico 40, alto 20, médio 8, baixo 3,
info 1). A penalidade de cada categoria é dividida por `1 + log2(hosts)`, e a
nota da categoria é `100·e^(−penalidade/20)`. A nota geral é a média ponderada
(rede 35%, TLS 25%, web 25%, vazamento 15%), com teto de 59 (F) se houver achado
crítico e de 79 (C) se houver achado alto. Conceitos: A ≥ 90, B ≥ 80, C ≥ 70,
D ≥ 60, F < 60.

### Salvaguardas

- Sem posse verificada não há varredura ativa; terceiros só em modo passivo.
- IPs internos/reservados resolvidos a partir de domínios de clientes são
  descartados antes da varredura, e a verificação HTTP não busca em domínios
  internos (proteção contra SSRF). `--allow-private-targets` desativa isso,
  apenas para laboratório.
- Senhas com scrypt; sessões `HttpOnly`/`SameSite=Strict` com token CSRF;
  chaves de API guardadas só como hash; limite de falhas de login por IP;
  cabeçalhos CSP, `X-Frame-Options` e `nosniff`.

## Testes

```bash
python -m unittest discover -s tests -v
```

Os testes de integração sobem servidores locais (HTTP, HTTPS autoassinado e
um serviço com banner SSH) e executam a varredura real contra eles. Os testes da
plataforma exercitam a API via HTTP: fluxo do parceiro, isolamento entre
tenants, CSRF, chaves de API, verificação de posse, ciclo de vida dos achados,
nota e extrato.

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
  platform/
    db.py            # esquema SQLite multi-tenant
    auth.py          # senhas, sessões, chaves de API, papéis
    scoring.py       # nota 0–100 / A–F por categoria
    verification.py  # verificação de posse (DNS TXT / HTTP)
    partners.py      # planos, níveis, extrato do parceiro
    engine.py        # varredura ativa/passiva + ciclo de vida dos achados
    worker.py        # fila e agendamento
    web.py           # API REST + servidor do painel
    report_html.py   # relatório executivo white-label
    demo.py          # dados sintéticos
    static/          # painel web (HTML/CSS/JS)
```
