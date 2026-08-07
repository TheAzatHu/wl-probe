#!/usr/bin/env python3
"""Сборка итога: гео, ASN, квоты по провайдерам, публикация."""
import argparse, collections, glob, json, os, socket, sys, urllib.parse

try:
    import maxminddb
except ImportError:
    maxminddb = None

_geo_cache = {}


def geo(addr, country_db, asn_db):
    if addr in _geo_cache:
        return _geo_cache[addr]
    ip = addr
    try:
        socket.inet_aton(addr)
    except OSError:
        try:
            ip = socket.gethostbyname(addr)
        except Exception:
            _geo_cache[addr] = (None, None, None)
            return _geo_cache[addr]
    cc = asn = org = None
    if country_db:
        try:
            r = country_db.get(ip) or {}
            cc = ((r.get("country") or {}).get("iso_code")
                  or (r.get("registered_country") or {}).get("iso_code"))
        except Exception:
            pass
    if asn_db:
        try:
            r = asn_db.get(ip) or {}
            asn = r.get("autonomous_system_number")
            org = r.get("autonomous_system_organization")
        except Exception:
            pass
    _geo_cache[addr] = (cc, asn, org)
    return _geo_cache[addr]


def render(item):
    """Метка со страной, провайдером и категорией — в фрагмент ссылки."""
    frag = (f"[CC={item.get('country_code') or 'ZZ'}]"
            f"[POOL={'WHITE' if item['category'] == 'whitelist' else 'GENERAL'}]"
            f"[ASN={item.get('asn') or 0}]"
            f" {(item.get('asn_org') or 'unknown')[:40]}")
    base = item["line"].split("#")[0]
    return base + "#" + urllib.parse.quote(frag, safe="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--per-asn", type=int, default=4)
    ap.add_argument("--per-endpoint", type=int, default=2)
    a = ap.parse_args()

    cdb = adb = None
    if maxminddb:
        for p, name in (("geo/country.mmdb", "c"), ("geo/asn.mmdb", "a")):
            if os.path.exists(p):
                try:
                    db = maxminddb.open_database(p)
                    if name == "c":
                        cdb = db
                    else:
                        adb = db
                except Exception:
                    pass

    items, per_source = [], collections.Counter()
    for path in sorted(glob.glob(a.glob)):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    it = json.loads(line)
                    items.append(it)
                    per_source[it["source"]] += 1

    # дедупликация по отпечатку между источниками, лучший trust побеждает
    best = {}
    for it in items:
        fp = it["fingerprint"]
        cur = best.get(fp)
        if cur is None or it["trust"] > cur["trust"]:
            best[fp] = it
    items = list(best.values())

    for it in items:
        cc, asn, org = geo(it["address"], cdb, adb)
        it["country_code"] = cc or "ZZ"
        it["asn"] = asn
        it["asn_org"] = org

    items.sort(key=lambda x: (-x["http_checks_passed"], x["http_ms"], -x["trust"]))

    asn_count, ep_count, picked = collections.Counter(), collections.Counter(), []
    for it in items:
        key_asn = it.get("asn") or f"ip:{it['address']}"
        key_ep = (it["address"], it["port"])
        if asn_count[key_asn] >= a.per_asn or ep_count[key_ep] >= a.per_endpoint:
            continue
        asn_count[key_asn] += 1
        ep_count[key_ep] += 1
        picked.append(it)

    os.makedirs(a.outdir, exist_ok=True)
    ru = [x for x in picked if x["country_code"] == "RU"]
    with open(f"{a.outdir}/alive.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(render(x) for x in picked) + "\n")
    with open(f"{a.outdir}/alive_ru.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(render(x) for x in ru) + "\n")
    with open(f"{a.outdir}/alive.jsonl", "w", encoding="utf-8") as f:
        for x in picked:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")

    stats = {
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
        "http_alive_total": len(items),
        "published": len(picked),
        "published_ru": len(ru),
        "by_country": dict(collections.Counter(x["country_code"] for x in picked).most_common(20)),
        "by_source": dict(per_source.most_common()),
        "by_category": dict(collections.Counter(x["category"] for x in picked)),
        "top_asn": dict(collections.Counter(
            f"{x.get('asn')} {x.get('asn_org')}" for x in picked).most_common(10)),
    }
    with open(f"{a.outdir}/stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    print(json.dumps(stats, ensure_ascii=False, indent=1)[:1200])


if __name__ == "__main__":
    sys.exit(main())
