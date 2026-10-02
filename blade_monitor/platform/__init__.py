"""Blade Monitor Platform — gestão de superfície de ataque multi-tenant.

Camadas:
  db.py            esquema SQLite e acesso a dados
  auth.py          senhas, sessões, chaves de API e papéis
  scoring.py       nota de segurança (0–100, A–F) por categoria
  verification.py  verificação de posse de ativos (DNS TXT / arquivo HTTP)
  partners.py      programa de parceiros: níveis, preços, extrato
  engine.py        execução de varreduras e ciclo de vida dos achados
  worker.py        fila e agendamento de varreduras
  web.py           API REST + painel web (stdlib http.server)
  report_html.py   relatório executivo white-label
"""
