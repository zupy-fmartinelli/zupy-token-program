"""Story 37.1 — real mainnet instruction data of zupy-token-program, up to 5 per instruction type. Read-only, public RPC.
Output: samples/mainnet-ix.jsonl  ({"name", "signature", "slot", "data_hex", "n_accounts"} per line)
"""

import base64, collections, hashlib, json, pathlib, time, urllib.request
from solders.transaction import VersionedTransaction

RPC = "https://api.mainnet-beta.solana.com"
PROGRAM = "ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU"  # pragma: allowlist secret
NAMES = [
    "initialize_token",
    "initialize_metadata",
    "update_metadata_field",
    "mint_tokens",
    "treasury_restock_pool",
    "transfer_from_pool",
    "return_to_pool",
    "transfer_company_to_user",
    "transfer_user_to_company",
    "execute_split_transfer",
    "initialize_rate_limit",
    "set_paused",
    "create_zupy_card",
    "create_coupon_nft",
    "mint_coupon_cnft",
    "withdraw_to_external",
    "return_user_to_pool",
    "consolidate_leaves",
]
BY = {hashlib.sha256(f"global:{n}".encode()).digest()[:8]: n for n in NAMES}
PER_TYPE, PAGES = 5, 4


def rpc(m, p):
    for _ in range(6):
        try:
            r = urllib.request.Request(
                RPC,
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                {"content-type": "application/json"},
            )
            return json.load(urllib.request.urlopen(r, timeout=30))["result"]
        except Exception:
            time.sleep(3)
    raise RuntimeError(m)


got, out, before = collections.Counter(), [], None
for _ in range(PAGES):
    opts = {"limit": 1000, **({"before": before} if before else {})}
    sigs = rpc("getSignaturesForAddress", [PROGRAM, opts])
    if not sigs:
        break
    before = sigs[-1]["signature"]
    for s in sigs:
        if s["err"] is not None:
            continue
        r = rpc("getTransaction", [s["signature"], {"encoding": "base64", "maxSupportedTransactionVersion": 0}])
        time.sleep(0.25)
        if not r:
            continue
        m = VersionedTransaction.from_bytes(base64.b64decode(r["transaction"][0])).message
        for ix in m.instructions:
            if str(m.account_keys[ix.program_id_index]) != PROGRAM:
                continue
            data = bytes(ix.data)
            name = BY.get(data[:8])
            if name and got[name] < PER_TYPE:
                got[name] += 1
                out.append(
                    {
                        "name": name,
                        "signature": s["signature"],
                        "slot": s["slot"],
                        "data_hex": data.hex(),
                        "n_accounts": len(bytes(ix.accounts)),
                    }
                )
        if len(got) >= 7 and all(v >= PER_TYPE for v in got.values()):
            break
    print("so far:", dict(got))
p = pathlib.Path(__file__).with_name("samples")
p.mkdir(exist_ok=True)
(p / "mainnet-ix.jsonl").write_text("".join(json.dumps(o) + "\n" for o in out))
print("wrote", len(out), "samples:", dict(sorted(got.items())))
