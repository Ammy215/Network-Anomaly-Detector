# NetSentinel

NetSentinel watches network traffic, learns what "normal" looks like for that network, flags the traffic that *doesn't* look normal, and uses AI — grounded in real security references via RAG, not guesses — to explain why it's abnormal and what an analyst should check next.

It is a **detection and investigation** tool, not an attack tool, and it never claims certainty it doesn't have. Full requirements and design decisions live in [`docs/PROJECT.md`](docs/PROJECT.md); the phased build plan and test gates live in [`docs/PHASE-2-PLAN.md`](docs/PHASE-2-PLAN.md).

## Live demo

**https://network-anomaly-detector-inky.vercel.app**

The dashboard, PCAP upload/analysis, ML scoring, AI investigation, threat-intel
enrichment, auth, and RBAC are all live and free. **Live packet capture is
local-only** — free hosting doesn't grant a container raw-socket access, so
that one feature is demoed by running the app locally (see below), not on
the hosted instance. See [`docs/PROJECT.md`](docs/PROJECT.md) §8 for the full
reasoning. Full deploy-from-scratch steps: [`docs/DEPLOYMENT-WALKTHROUGH.md`](docs/DEPLOYMENT-WALKTHROUGH.md).

## Status: Phase 14 — Deployed

All phases (0-13) plus an extended pre-deployment hardening pass are complete:
packet capture and flow assembly, ML anomaly scoring, RAG-grounded AI
investigation, threat-intel enrichment, auth/RBAC, and adversarial security
testing. This phase adds the free public deployment described above.

## Stack

- **Frontend:** React 19 + Vite + Tailwind CSS
- **Backend:** Python + FastAPI
- **Database / Auth:** Supabase (Postgres)
- **Hosting:** free-tier only, everywhere — frontend on Vercel, backend on Render
- **Local dev:** no Docker — everything runs manually so every moving part is
  understood. The backend's `Dockerfile` exists solely for deployment (Render
  needs it to install `tshark`, a hard dependency of PCAP parsing); it is not
  part of the local development workflow.

## Running it locally

**Backend**

> **The venv must be active in every terminal before `pip install` or `uvicorn`.**
> Installing into the global Python instead of the venv is what causes
> hard-to-diagnose dependency conflicts (e.g. a stale `pyparsing` from an
> unrelated global package silently breaking the Supabase client's import
> chain). Check `where python` (PowerShell) resolves to
> `backend\.venv\Scripts\python.exe` before running anything.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
Copy-Item ..\.env.example .env
uvicorn app.main:app --reload --port 8000
```
Visit `http://localhost:8000/api/health` — should return `{"status":"ok"}`.

Each new terminal session needs `.venv\Scripts\activate` run again before
`uvicorn` — activation doesn't persist across terminals.

**Frontend** (separate terminal)
```powershell
cd frontend
npm install
npm run dev
```
Visit `http://localhost:5173` — should show the health-check result fetched from the backend.

## Supabase setup (manual, one-time)

1. Sign up free at https://supabase.com/dashboard/sign-up and create a project.
2. Copy the project URL and anon key into `backend/.env` (`SUPABASE_URL`, `SUPABASE_ANON_KEY`).
3. Nothing in Phase 0 calls Supabase yet — this just gets it ready for Phase 1 onward.

## Project docs

- [`docs/PROJECT.md`](docs/PROJECT.md) — requirements & decisions
- [`docs/PHASE-2-PLAN.md`](docs/PHASE-2-PLAN.md) — phased build plan & test gates
- [`docs/DEPLOYMENT-WALKTHROUGH.md`](docs/DEPLOYMENT-WALKTHROUGH.md) — deploy from scratch, step by step
- [`docs/CLAUDE_CONTEXT.md`](docs/CLAUDE_CONTEXT.md) — author's stack/style rules
- [`CLAUDE.md`](CLAUDE.md) — project rules for Claude Code sessions

## License

MIT — see [LICENSE](LICENSE).
