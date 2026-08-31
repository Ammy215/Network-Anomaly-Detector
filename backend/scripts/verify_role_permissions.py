"""Verify role-based permissions against a running backend, end to end.

Run:  python scripts/verify_role_permissions.py
      python scripts/verify_role_permissions.py --base http://127.0.0.1:8000

Checks every role-gated surface with real tokens for the three real
accounts, and asserts an exact expected status per (endpoint, role) --
403 where a role must be refused, 200 where it must be allowed. Also
checks that a missing, malformed, or tampered token is rejected.

Self-contained on purpose: it mints its own fresh sessions through
Supabase's admin `generate_link` + `verify` flow, so it never fails with
a stale-token 401 that looks exactly like an auth defect. No passwords
are needed or stored; the service-role key is read from backend/.env at
runtime and never printed.

Written for the pre-deployment readiness pass (Phase 13.5) and kept so the
same checks can be re-run against a deployed instance -- point `--base` at
the deployed URL. See docs/PRE-DEPLOYMENT-READINESS.md.
"""

import argparse
import sys
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

ACCOUNTS = {
    "admin": "ammar.badlawala@gmail.com",
    "analyst": "badlawalaammar0113@gmail.com",
    "viewer": "a.badlawala@somaiya.edu",
}


def read_env() -> dict:
    env = {}
    for line in (BACKEND_DIR / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def mint(url: str, service_key: str, anon_key: str, email: str) -> str:
    """A real session for `email`, without needing its password."""
    with httpx.Client(timeout=60.0) as client:
        link = client.post(
            f"{url}/auth/v1/admin/generate_link",
            headers={"apikey": service_key, "Authorization": f"Bearer {service_key}",
                     "Content-Type": "application/json"},
            json={"type": "magiclink", "email": email},
        )
        link.raise_for_status()
        verified = client.post(
            f"{url}/auth/v1/verify",
            headers={"apikey": anon_key, "Content-Type": "application/json"},
            json={"type": "magiclink", "token_hash": link.json()["hashed_token"]},
        )
        verified.raise_for_status()
        return verified.json()["access_token"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000",
                        help="backend base URL (default: http://127.0.0.1:8000)")
    base = parser.parse_args().base.rstrip("/")

    env = read_env()
    missing = [k for k in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY") if not env.get(k)]
    if missing:
        print(f"backend/.env is missing: {', '.join(missing)}")
        return 2

    print(f"target: {base}")
    print("minting fresh sessions for the three real accounts...")
    tokens = {role: mint(env["SUPABASE_URL"], env["SUPABASE_SERVICE_ROLE_KEY"],
                         env["SUPABASE_ANON_KEY"], email)
              for role, email in ACCOUNTS.items()}
    headers = {role: {"Authorization": f"Bearer {tok}"} for role, tok in tokens.items()}
    print("  done\n")

    failures = 0
    with httpx.Client(timeout=180.0) as client:
        print("=== 1. role reported by the API for each account ===")
        for role in ("admin", "analyst", "viewer"):
            me = client.get(f"{base}/api/auth/me", headers=headers[role]).json()
            actual = me.get("role")
            ok = actual == role
            failures += 0 if ok else 1
            print(f"  {role:8s} -> role={actual}  {'' if ok else '  MISMATCH'}")

        flows = client.get(f"{base}/api/flows", headers=headers["admin"]).json()["flows"]
        if not flows:
            print("\nno flows stored -- upload a PCAP first, several checks need one.")
            return 2
        any_flow = flows[0]["id"]
        # investigate/enrichment are gated to FLAGGED flows, so those rows need
        # an anomalous one or every role legitimately gets 400, not 403/200.
        flagged = next((f["id"] for f in flows if f.get("is_anomalous")), any_flow)

        matrix = [
            ("GET", "/api/flows", None, {"viewer": 200, "analyst": 200, "admin": 200}),
            ("GET", "/api/verdicts/summary", None, {"viewer": 200, "analyst": 200, "admin": 200}),
            ("GET", "/api/models", None, {"viewer": 200, "analyst": 200, "admin": 200}),
            ("POST", f"/api/flows/{any_flow}/verdict", {"verdict": "benign"},
             {"viewer": 403, "analyst": 200, "admin": 200}),
            ("POST", "/api/capture/start", {"interface": "__nonexistent__"},
             {"viewer": 403, "analyst": 400, "admin": 400}),
            ("GET", "/api/admin/users", None, {"viewer": 403, "analyst": 403, "admin": 200}),
            ("GET", "/api/admin/audit-log", None, {"viewer": 403, "analyst": 403, "admin": 200}),
            ("POST", "/api/rag/search", {"query": "port scan", "top_k": 2},
             {"viewer": 403, "analyst": 403, "admin": 200}),
            ("POST", f"/api/flows/{flagged}/investigate", {"fetch": False},
             {"viewer": 200, "analyst": 200, "admin": 200}),
            ("POST", f"/api/flows/{flagged}/enrichment", {"fetch": False},
             {"viewer": 200, "analyst": 200, "admin": 200}),
        ]

        print("\n=== 2. role matrix (403 = correctly refused) ===")
        print(f"  {'endpoint':46s} {'viewer':>11s} {'analyst':>11s} {'admin':>11s}")
        for method, path, body, expected in matrix:
            cells = []
            for role in ("viewer", "analyst", "admin"):
                kwargs = {"headers": headers[role]}
                if body is not None:
                    kwargs["json"] = body
                got = client.request(method, base + path, **kwargs).status_code
                ok = got == expected[role]
                failures += 0 if ok else 1
                cells.append(str(got) if ok else f"{got}!={expected[role]}")
            label = f"{method} {path.replace(any_flow, '{id}').replace(flagged, '{id}')}"
            print(f"  {label:46s} {cells[0]:>11s} {cells[1]:>11s} {cells[2]:>11s}")

        print("\n=== 3. no token / malformed / tampered signature ===")
        tampered = tokens["admin"].rsplit(".", 1)[0] + ".TAMPERED"
        for label, hdr in (
            ("no token", {}),
            ("malformed", {"Authorization": "Bearer not.a.jwt"}),
            ("tampered signature", {"Authorization": f"Bearer {tampered}"}),
        ):
            got = client.get(f"{base}/api/flows", headers=hdr).status_code
            ok = got == 401
            failures += 0 if ok else 1
            print(f"  {label:22s} -> {got} {'' if ok else '  EXPECTED 401'}")

    print(f"\n=== RESULT: {failures} unexpected ===")
    print(f"note: a verdict was written on flow {any_flow} by analyst and admin;")
    print("      delete it if you want the database left pristine.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
