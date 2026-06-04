import json, os, time, urllib.request

BASE = "http://localhost:8001/api"
CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "test_contracts")

FILES = [
    "EtherStore.sol",
    "TxOriginWallet.sol",
    "Suicidal.sol",
    "UncheckedCall.sol",
    "AccessControl.sol",
]

def post_analyze(code):
    payload = json.dumps({"code": code}).encode()
    req = urllib.request.Request(
        f"{BASE}/analyze", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read())

def has_chinese(text):
    return any('一' <= c <= '鿿' for c in text)

results = []
for fname in FILES:
    path = os.path.join(CONTRACTS_DIR, fname)
    with open(path, encoding="utf-8") as f:
        code = f.read()

    print(f"\n{'='*60}\nAnalyzing: {fname}\n{'='*60}")
    t0 = time.time()
    try:
        resp = post_analyze(code)
        elapsed = round(time.time() - t0)
        if resp.get("status") == "success":
            d = resp["data"]
            summary    = d.get("summary", "")
            attack     = str(d.get("attackStrategy", {}).get("steps", []))
            defense    = str(d.get("defenseRecommendations", []))
            score_expl = d.get("scoreExplanation", "")
            all_text   = summary + attack + defense + score_expl
            lang = "中文" if has_chinese(all_text) else "English"
            row = {
                "contract":       fname,
                "slitherSuccess": d.get("slitherSuccess"),
                "vulnCount":      len(d.get("vulnerabilities", [])),
                "causalPaths":    len(d.get("causalPaths", [])),
                "language":       lang,
                "score":          d.get("securityScore"),
                "elapsed_s":      elapsed,
                "summary_snippet": summary[:120],
            }
            results.append(row)
            print(f"  slitherSuccess : {row['slitherSuccess']}")
            print(f"  vulnCount      : {row['vulnCount']}")
            print(f"  causalPaths    : {row['causalPaths']}")
            print(f"  language       : {row['language']}")
            print(f"  score          : {row['score']}")
            print(f"  time           : {elapsed}s")
            print(f"  summary        : {summary[:100]}")
        else:
            print(f"  ERROR: {resp.get('message')}")
            results.append({"contract": fname, "error": resp.get("message")})
    except Exception as e:
        print(f"  EXCEPTION ({round(time.time()-t0)}s): {e}")
        results.append({"contract": fname, "error": str(e)})

# Check topVulns from DB
print("\n\n" + "="*60 + "\nDB topVulns (duplicate check)\n" + "="*60)
try:
    with urllib.request.urlopen(f"{BASE}/analyses/stats", timeout=10) as r:
        stats = json.loads(r.read())
    if stats.get("status") == "success":
        for v in stats["data"]["topVulns"]:
            print(f"  {v['type']:<35} count={v['count']}")
except Exception as e:
    print(f"  stats error: {e}")

# Summary table
print("\n\n" + "="*60 + "\nSUMMARY TABLE\n" + "="*60)
print(f"{'Contract':<22} {'Slither':^7} {'Vulns':^5} {'Paths':^5} {'Lang':^8} {'Score':^5}")
print("-"*60)
for r in results:
    if "error" in r:
        print(f"{r['contract']:<22} ERROR: {r['error'][:30]}")
    else:
        print(f"{r['contract']:<22} {str(r['slitherSuccess']):^7} {r['vulnCount']:^5} {r['causalPaths']:^5} {r['language']:^8} {r['score']:^5}")

with open("test_results_v2.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print("\nSaved to test_results_v2.json")
