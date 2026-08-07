#!/usr/bin/env python3
"""Стадия A+B: загрузка источника, нормализация, честная дедупликация, TCP-проба.

Запускается по одному экземпляру на источник (матрица GitHub Actions).
На выходе — JSONL с кандидатами, дошедшими до TCP.
"""
import argparse, base64, concurrent.futures as cf, hashlib, json, re, socket, sys, time
import urllib.parse, urllib.request

ALLOWED_SECURITY = {"tls", "reality", "none", ""}
ALLOWED_NETWORK = {"raw", "tcp", "ws", "grpc", "httpupgrade", "xhttp", "h2"}
# xhttp собираем, но помечаем — публиковать его нельзя, пока не подтверждена
# совместимость с ядром Karing. Отдельная очередь, а не молчаливое выбрасывание.
QUARANTINE_NETWORK = {"xhttp", "h2"}

UA = "wl-probe/1.0 (+https://github.com/TheAzatHu/wl-probe)"


def fetch(url, max_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/plain,*/*"})
    with urllib.request.urlopen(req, timeout=60) as r:
        if not r.url.startswith("https://"):
            raise ValueError("downgrade to http is not allowed")
        return r.read(max_bytes)


def maybe_b64(text):
    stripped = re.sub(r"\s+", "", text)
    if "://" in text[:4096]:
        return text
    if len(stripped) > 128 and re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        try:
            decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4)).decode("utf-8", "replace")
            if "://" in decoded:
                return decoded
        except Exception:
            pass
    return text


def parse(line):
    """Разбор vless:// в нормализованный словарь. None — если мусор."""
    line = line.strip()
    if not line.lower().startswith("vless://"):
        return None
    m = re.match(r"vless://([^@]+)@\[?([^\]/?#]+?)\]?:(\d+)/?\?([^#]*)(?:#(.*))?$", line)
    if not m:
        return None
    uid, host, port, query, label = m.groups()
    uid = urllib.parse.unquote(uid)
    if len(uid) < 8:
        return None
    if not host or host in ("0.0.0.0", "127.0.0.1", "::"):
        return None
    port = int(port)
    if not 1 <= port <= 65535:
        return None
    q = {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
    net = (q.get("type") or "tcp").lower()
    if net == "tcp":
        net = "raw"
    sec = (q.get("security") or "none").lower()
    if net not in ALLOWED_NETWORK or sec not in ALLOWED_SECURITY:
        return None
    if sec == "reality" and not q.get("pbk"):
        return None
    return {
        "uuid": uid, "address": host, "port": port,
        "network": net, "security": sec,
        "sni": q.get("sni") or q.get("peer") or "",
        "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
        "fp": q.get("fp", ""), "flow": q.get("flow", ""),
        "path": q.get("path", ""), "host": q.get("host", ""),
        "service": q.get("serviceName") or q.get("servicename") or "",
        "alpn": q.get("alpn", ""), "encryption": q.get("packetEncoding", ""),
        "label": urllib.parse.unquote(label or "")[:120],
        "line": line,
    }


def fingerprint(item):
    """Полный технический отпечаток.

    Два конфига на одном IP:порту — РАЗНЫЕ, если отличаются UUID, SNI,
    Reality-ключом, транспортом, путём или Host. Схлопывать их по IP:порту,
    как делают MyAppVPN и FLAT447, значит терять рабочие варианты.
    """
    parts = [item[k] for k in ("address", "port", "uuid", "security", "flow",
                               "network", "sni", "pbk", "sid", "fp",
                               "path", "host", "service", "alpn", "encryption")]
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def tcp_probe(endpoint, timeout=2.5):
    host, port = endpoint
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return endpoint, round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return endpoint, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--category", required=True)
    ap.add_argument("--trust", type=int, default=50)
    ap.add_argument("--urls", required=True, help="через запятую")
    ap.add_argument("--max-bytes", type=int, default=20_000_000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    raw, report = "", []
    for url in a.urls.split(","):
        url = url.strip()
        if not url.startswith("https://"):
            report.append({"url": url, "ok": False, "error": "non-https"})
            continue
        try:
            body = fetch(url, a.max_bytes)
            text = maybe_b64(body.decode("utf-8", "replace"))
            n = sum(1 for l in text.splitlines() if l.strip().lower().startswith("vless://"))
            report.append({"url": url, "ok": True, "bytes": len(body), "vless": n,
                           "sha256": hashlib.sha256(body).hexdigest()[:16]})
            if n:
                raw += text + "\n"
        except Exception as e:
            report.append({"url": url, "ok": False, "error": str(e)[:120]})

    seen, items, quarantine = set(), [], []
    for line in raw.splitlines():
        it = parse(line)
        if not it:
            continue
        fp = fingerprint(it)
        if fp in seen:
            continue
        seen.add(fp)
        it["fingerprint"] = fp
        it["source"] = a.id
        it["category"] = a.category
        it["trust"] = a.trust
        (quarantine if it["network"] in QUARANTINE_NETWORK else items).append(it)

    endpoints = sorted({(x["address"], x["port"]) for x in items})
    rtt = {}
    if endpoints:
        with cf.ThreadPoolExecutor(max_workers=128) as ex:
            for ep, ms in ex.map(tcp_probe, endpoints):
                rtt[ep] = ms
    alive = []
    for it in items:
        ms = rtt.get((it["address"], it["port"]))
        if ms is not None:
            it["tcp_ms"] = ms
            alive.append(it)

    with open(a.out, "w", encoding="utf-8") as f:
        for it in alive:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    stats = {"source": a.id, "category": a.category,
             "urls": report, "unique_configs": len(items),
             "quarantined_xhttp": len(quarantine),
             "tcp_endpoints": len(endpoints), "tcp_alive": len(alive)}
    with open(a.out + ".stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    print(json.dumps(stats, ensure_ascii=False)[:900])
    if not alive:
        print(f"::warning::источник {a.id} не дал ни одного живого узла")


if __name__ == "__main__":
    sys.exit(main())
