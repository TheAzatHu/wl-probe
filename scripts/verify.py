#!/usr/bin/env python3
"""Стадия C: реальный проход через каждый узел.

Поднимает Xray с одним outbound, слушающий локальный SOCKS, и ходит через него
на несколько контрольных адресов. TCP-доступность сама по себе успехом
не считается — узел должен реально пропустить HTTP.
"""
import argparse, concurrent.futures as cf, json, os, socket, subprocess, sys, tempfile, time
import urllib.request

XRAY = os.environ.get("XRAY_BIN", "xray")
CHECKS = [
    ("https://cp.cloudflare.com/generate_204", 204),
    ("https://www.gstatic.com/generate_204", 204),
]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_config(item, port):
    q = item
    stream = {"network": q["network"], "security": q["security"] or "none"}
    if q["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": q["sni"], "publicKey": q["pbk"],
            "shortId": q["sid"], "fingerprint": q["fp"] or "chrome",
        }
    elif q["security"] == "tls":
        tls = {"serverName": q["sni"] or q["host"] or q["address"]}
        if q["fp"]:
            tls["fingerprint"] = q["fp"]
        if q["alpn"]:
            tls["alpn"] = q["alpn"].split(",")
        stream["tlsSettings"] = tls
    if q["network"] == "ws":
        ws = {"path": q["path"] or "/"}
        if q["host"]:
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws
    elif q["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": (q["service"] or q["path"]).lstrip("/")}
    elif q["network"] == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": q["path"] or "/", "host": q["host"]}
    user = {"id": q["uuid"], "encryption": "none"}
    if q["flow"]:
        user["flow"] = q["flow"]
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "in", "port": port, "listen": "127.0.0.1",
                      "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}}],
        "outbounds": [{"tag": "out", "protocol": "vless", "settings": {"vnext": [
            {"address": q["address"], "port": q["port"], "users": [user]}]},
            "streamSettings": stream}],
    }


def wait_port(port, deadline=3.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def probe(item):
    port = free_port()
    cfg = build_config(item, port)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    proc = None
    try:
        proc = subprocess.Popen([XRAY, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(port):
            return None
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"socks5h://127.0.0.1:{port}",
                                         "https": f"socks5h://127.0.0.1:{port}"}))
        passed, best = 0, None
        for url, expect in CHECKS:
            try:
                t0 = time.monotonic()
                with opener.open(url, timeout=8) as r:
                    if r.status in (expect, 200):
                        passed += 1
                        ms = round((time.monotonic() - t0) * 1000, 1)
                        best = ms if best is None else min(best, ms)
            except Exception:
                pass
        if passed == 0:
            return None
        out = dict(item)
        out["http_checks_passed"] = passed
        out["http_ms"] = best
        return out
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--limit", type=int, default=4000)
    a = ap.parse_args()

    items = []
    with open(a.inp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    items.sort(key=lambda x: x.get("tcp_ms", 9e9))
    items = items[: a.limit]

    ok = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for res in ex.map(probe, items):
            if res:
                ok.append(res)
    ok.sort(key=lambda x: (-x["http_checks_passed"], x["http_ms"]))
    with open(a.out, "w", encoding="utf-8") as f:
        for it in ok:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    print(json.dumps({"probed": len(items), "http_alive": len(ok)}, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
