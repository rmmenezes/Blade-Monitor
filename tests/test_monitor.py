import http.server
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from blade_monitor import cli
from blade_monitor.config import load_config
from blade_monitor.diff import compare
from blade_monitor.discovery import expand_ip_targets, is_excluded, parse_crtsh
from blade_monitor.models import Finding, HTTPInfo, Service, Snapshot, TLSInfo
from blade_monitor.report import alert_text
from blade_monitor.rules import evaluate
from blade_monitor.scanner import hostname_matches, scan
from blade_monitor.storage import Storage


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"<html><head><title>Index of /backup</title></head></html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.18.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def _banner_server(banner: bytes):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()

    def loop():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                conn.sendall(banner)
            except OSError:
                pass
            conn.close()
    threading.Thread(target=loop, daemon=True).start()
    return sock


class UnitTests(unittest.TestCase):
    def test_parse_crtsh(self):
        data = [{"name_value": "*.a.example.com\nwww.example.com"},
                {"name_value": "evil-example.com"}, {"name_value": "example.com."}]
        self.assertEqual(parse_crtsh(data, "example.com"),
                         {"a.example.com", "www.example.com", "example.com"})

    def test_exclusion_and_cidr(self):
        self.assertTrue(is_excluded("x.dev.example.com", ["*.dev.example.com"]))
        self.assertFalse(is_excluded("www.example.com", ["*.dev.example.com"]))
        self.assertEqual(expand_ip_targets(["10.0.0.0/30", "1.2.3.4"]),
                         ["10.0.0.1", "10.0.0.2", "1.2.3.4"])
        with self.assertRaises(ValueError):
            expand_ip_targets(["10.0.0.0/8"])

    def test_hostname_matches(self):
        self.assertTrue(hostname_matches("a.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("a.b.example.com", ["*.example.com"]))
        self.assertTrue(hostname_matches("example.com", ["example.com"]))

    def test_rules(self):
        svcs = [
            Service("db.example.com", "1.1.1.1", 6379),
            Service("www.example.com", "1.1.1.2", 443,
                    tls=TLSInfo(days_left=5, not_after="x", self_signed=True,
                                hostname_match=False, protocol="TLSv1")),
            Service("www.example.com", "1.1.1.2", 80,
                    http=HTTPInfo(status=200, redirect_to_https=False, server="Apache/2.4.1")),
        ]
        rules = {(f.rule, f.severity) for f in evaluate(svcs)}
        self.assertIn(("risky-port", "critical"), rules)
        self.assertIn(("cert-expiring", "medium"), rules)
        self.assertIn(("cert-self-signed", "medium"), rules)
        self.assertIn(("cert-hostname-mismatch", "medium"), rules)
        self.assertIn(("weak-tls", "medium"), rules)
        self.assertIn(("http-no-redirect", "low"), rules)
        self.assertIn(("server-version-disclosure", "low"), rules)

    def test_diff_and_alert(self):
        old = Snapshot("t0", hosts={"a.example.com": ["1.1.1.1"]},
                       services=[Service("a.example.com", "1.1.1.1", 443)],
                       findings=[Finding("cert-expiring", "medium", "a.example.com:443", "x")])
        new = Snapshot("t1", hosts={"a.example.com": ["1.1.1.1"], "b.example.com": ["1.1.1.2"]},
                       services=[Service("b.example.com", "1.1.1.2", 3389)],
                       findings=[Finding("risky-port", "high", "b.example.com:3389", "RDP")])
        ch = compare(old, new)
        self.assertEqual(ch.new_hosts, ["b.example.com"])
        self.assertEqual(ch.new_services, ["b.example.com:3389"])
        self.assertEqual(ch.closed_services, ["a.example.com:443"])
        self.assertEqual([f.rule for f in ch.new_findings], ["risky-port"])
        self.assertEqual([f.rule for f in ch.resolved_findings], ["cert-expiring"])
        self.assertIn("RDP", alert_text(ch, "medium"))
        self.assertIsNone(alert_text(compare(new, new), "medium"))

    def test_storage_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            st = Storage(os.path.join(d, "x.db"))
            snap = Snapshot("t0", "t1", {"h": ["1.1.1.1"]},
                            [Service("h", "1.1.1.1", 443, tls=TLSInfo(days_left=3))],
                            [Finding("r", "low", "h:443", "t")])
            sid = st.save(snap)
            self.assertEqual(st.latest()[0], sid)
            self.assertEqual(st.get(sid), snap)
            self.assertIsNone(st.latest(before_id=sid))
            st.close()


@unittest.skipUnless(shutil.which("openssl"), "openssl necessário")
class IntegrationTests(unittest.TestCase):
    """Varredura real contra serviços locais (HTTP, HTTPS autoassinado, banner)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = Path(cls.tmp.name, "c.pem"), Path(cls.tmp.name, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "10",
                        "-subj", "/CN=localhost"], check=True, capture_output=True)
        cls.http = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler))
        cls.https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.https.socket = ctx.wrap_socket(cls.https.socket, server_side=True)
        _serve(cls.https)
        cls.ssh = _banner_server(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        cls.ports = [cls.http.server_address[1], cls.https.server_address[1],
                     cls.ssh.getsockname()[1]]

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.https.shutdown()
        cls.ssh.close()
        cls.tmp.cleanup()

    def test_scan_detects_services(self):
        http_p, https_p, ssh_p = self.ports
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_p = closed.getsockname()[1]
        closed.close()

        svcs = {s.port: s for s in scan({"127.0.0.1": ["127.0.0.1"]},
                                        self.ports + [closed_p], timeout=2, workers=8)}
        self.assertEqual(set(svcs), set(self.ports))

        self.assertIsNone(svcs[http_p].tls)
        self.assertEqual(svcs[http_p].http.status, 200)
        self.assertEqual(svcs[http_p].http.title, "Index of /backup")

        tls = svcs[https_p].tls
        self.assertIsNotNone(tls)
        self.assertTrue(tls.self_signed)
        self.assertIn(tls.days_left, (9, 10))
        self.assertEqual(svcs[https_p].http.status, 200)

        self.assertTrue(svcs[ssh_p].banner.startswith("SSH-2.0-OpenSSH_8.9p1"))
        self.assertIsNone(svcs[ssh_p].http)

        rules = {(f.rule, f.asset) for f in evaluate(list(svcs.values()))}
        self.assertIn(("cert-self-signed", f"127.0.0.1:{https_p}"), rules)
        self.assertIn(("cert-expiring", f"127.0.0.1:{https_p}"), rules)
        self.assertIn(("sensitive-panel", f"127.0.0.1:{http_p}"), rules)
        self.assertIn(("banner-version", f"127.0.0.1:{ssh_p}"), rules)

    def test_cli_end_to_end(self):
        d = self.tmp.name
        cfg = Path(d, "config.toml")
        cfg.write_text(
            '[targets]\nips = ["127.0.0.1"]\n'
            f'[scan]\nports = {self.ports}\ntimeout = 2\nworkers = 8\n'
            f'[storage]\ndatabase = "{d}/m.db"\nreport_dir = "{d}/reports"\n')
        self.assertEqual(load_config(cfg).ips, ["127.0.0.1"])
        self.assertEqual(cli.main(["-c", str(cfg), "scan"]), 2)  # há achado "high"
        self.assertEqual(cli.main(["-c", str(cfg), "scan"]), 2)
        self.assertEqual(len(list(Path(d, "reports").glob("*.md"))), 2)
        self.assertEqual(cli.main(["-c", str(cfg), "history"]), 0)
        self.assertEqual(cli.main(["-c", str(cfg), "show"]), 0)


if __name__ == "__main__":
    unittest.main()
