# NetSentinel

NetSentinel watches network traffic, learns what "normal" looks like for that network, flags the traffic that *doesn't* look normal, and uses AI — grounded in real security references via RAG, not guesses — to explain why it's abnormal and what an analyst should check next.

It is a **detection and investigation** tool, not an attack tool, and it never claims certainty it doesn't have. Full requirements and design decisions live in [`docs/PROJECT.md`](docs/PROJECT.md); the phased build plan and test gates live in [`docs/PHASE-2-PLAN.md`](docs/PHASE-2-PLAN.md).

## Status: Phase 0 — Foundation

This is the empty-but-wired skeleton. **Nothing functional exists yet** — no packet capture, no flow assembly, no ML, no AI, no auth, no styling. The only thing this phase proves is that the backend and frontend are correctly wired to each other and the repo is set up correctly.

## Stack

- **Frontend:** React 18 + Vite + Tailwind CSS
- **Backend:** Python + FastAPI
- **Database / Auth:** Supabase (Postgres)
- **Hosting:** free-tier only, everywhere
- No Docker — everything runs manually so every moving part is understood.

## Running it locally

**Backend**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
Copy-Item ..\.env.example .env
uvicorn app.main:app --reload --port 8000
```
Visit `http://localhost:8000/api/health` — should return `{"status":"ok"}`.

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
- [`docs/CLAUDE_CONTEXT.md`](docs/CLAUDE_CONTEXT.md) — author's stack/style rules
- [`CLAUDE.md`](CLAUDE.md) — project rules for Claude Code sessions

## License

MIT — see [LICENSE](LICENSE).
