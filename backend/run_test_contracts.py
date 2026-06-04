import json, os, time, urllib.request, urllib.error

BASE = "http://localhost:8001/api"
CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "test_contracts")

FILES = [
    "EtherStore.sol",
    "TxOriginWallet.sol",
    "Suicidal.sol",
    "UncheckedCall.sol",
    "AccessControl.sol",
    "SafeBank.sol",
]

def post_analyze(code):
    payload = json.dumps({"code": code}).encode()
    req = urllib.request.Request(
        f"{BASE}/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read())

results = []
for fname in FILES:
    path = os.path.join(CONTRACTS_DIR, fname)
    with open(path, encoding="utf-8") as f:
        code = f.read()

    print(f"\n{'='*60}")
    print(f"Analyzing: {fname}")
    print("="*60)
    t0 = time.time()
    try:
        resp = post_analyze(code)
        elapsed = round(time.time() - t0)
        if resp.get("status") == "success":
            d = resp["data"]
            # detect language of summary
            summary = d.get("summary", "")
            has_chinese = any('一' <= c <= '鿿' for c in summary)
            lang = "中文" if has_chinese else "English"

            row = {
                "contract": fname,
                "slitherSuccess": d.get("slitherSuccess"),
                "vulnCount": len(d.get("vulnerabilities", [])),
                "causalPathsCount": len(d.get("causalPaths", [])),
                "language": lang,
                "score": d.get("securityScore"),
                "elapsed_s": elapsed,
            }
            results.append(row)
            print(f"  slitherSuccess : {row['slitherSuccess']}")
            print(f"  vulnCount      : {row['vulnCount']}")
            print(f"  causalPaths    : {row['causalPathsCount']}")
            print(f"  language       : {row['language']}")
            print(f"  score          : {row['score']}")
            print(f"  time           : {elapsed}s")
        else:
            print(f"  ERROR: {resp.get('message')}")
            results.append({"contract": fname, "error": resp.get("message")})
    except Exception as e:
        elapsed = round(time.time() - t0)
        print(f"  EXCEPTION: {e} (after {elapsed}s)")
        results.append({"contract": fname, "error": str(e)})

print("\n\n" + "="*60)
print("SUMMARY TABLE")
print("="*60)
print(f"{'Contract':<22} {'Slither':^7} {'Vulns':^5} {'Paths':^5} {'Lang':^8} {'Score':^5}")
print("-"*60)
for r in results:
    if "error" in r:
        print(f"{r['contract']:<22} ERROR: {r['error'][:30]}")
    else:
        print(f"{r['contract']:<22} {str(r['slitherSuccess']):^7} {r['vulnCount']:^5} {r['causalPathsCount']:^5} {r['language']:^8} {r['score']:^5}")

# save raw
with open("test_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print("\nFull results saved to test_results.json")
