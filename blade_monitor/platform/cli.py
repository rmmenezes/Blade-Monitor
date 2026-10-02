"""CLI da plataforma: blade-platform init | serve | worker | demo."""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys

from . import auth, demo
from .db import Database
from .engine import EngineSettings
from .web import App, Settings, serve
from .worker import Worker

log = logging.getLogger("blade_monitor.platform")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blade-platform",
                                     description="Plataforma de gestão de superfície de ataque")
    parser.add_argument("--db", default=os.environ.get("BLADE_DB", "blade_platform.db"))
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="cria o banco e o administrador da plataforma")
    p_init.add_argument("--email", required=True)
    p_init.add_argument("--name", default="Administrador")

    p_serve = sub.add_parser("serve", help="inicia API + painel web (e o worker)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--no-worker", action="store_true", help="não executa a fila neste processo")
    p_serve.add_argument("--secure-cookies", action="store_true", help="use atrás de HTTPS")
    p_serve.add_argument("--allow-private-targets", action="store_true",
                         help="aceita IPs privados/loopback (apenas laboratório)")

    p_worker = sub.add_parser("worker", help="executa apenas a fila de varreduras")
    p_worker.add_argument("--allow-private-targets", action="store_true",
                          help="permite varrer IPs privados/loopback (apenas laboratório)")
    sub.add_parser("demo", help="carrega dados sintéticos de demonstração")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    db = Database(args.db)

    if args.cmd == "init":
        password = os.environ.get("BLADE_ADMIN_PASSWORD") or getpass.getpass("Senha: ")
        try:
            auth.create_user(db, args.email, password, "admin", name=args.name)
        except auth.AuthError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        print(f"Administrador {args.email} criado em {args.db}.")
        return 0

    if args.cmd == "demo":
        info = demo.seed(db)
        print("Dados de demonstração criados. Senha de todos os usuários:", info["password"])
        for u in info["users"]:
            print("  -", u)
        return 0

    engine_settings = EngineSettings(allow_private=getattr(args, "allow_private_targets", False))
    if args.cmd == "worker":
        w = Worker(db, engine_settings)
        try:
            w.loop()
        except KeyboardInterrupt:
            pass
        return 0

    app = App(db, Settings(allow_private_targets=args.allow_private_targets,
                           secure_cookies=args.secure_cookies, engine=engine_settings))
    w = None if args.no_worker else Worker(db, engine_settings).start()
    server = serve(app, args.host, args.port)
    print(f"Blade Monitor Platform em http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if w:
            w.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
