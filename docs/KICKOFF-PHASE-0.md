# NetSentinel — What To Do Now (Build-Phase 0)

You have two Claude surfaces, and they do different jobs:
- **This chat (guidance Claude)** — planning, prompts, decisions, sanity-checks.
- **Claude Code in VS Code** — the actual builder.

The steps below get Claude Code building. You do steps 1–4 once, by hand. Then you paste the prompt in step 5 into Claude Code, and it does Phase 0.

---

## Step 1 — Get the empty repo onto your machine
Open the VS Code terminal (Windows) and clone the repo you already made:
```
git clone https://github.com/Ammy215/Network-Anomaly-Detector.git
cd Network-Anomaly-Detector
```
(If it's already cloned, just `cd` into it.)

## Step 2 — Put the context files where Claude Code can read them
Make a `docs` folder and drop these 8 files into it (the ones from this project):
```
docs/CLAUDE_CONTEXT.md
docs/PROJECT.md
docs/PHASE-2-PLAN.md
docs/network-anomaly-detection-prompt.md
docs/how-real-projects-get-built.md
docs/systems-design-vocabulary-reference.md
docs/mcp-connectors-plugins-skills-reference.md
docs/frontend-resources-reference.md
```
That's it — you do **not** paste these into the Claude Code chat. They live in the repo, and Claude Code reads them itself (much better — it persists across every future session instead of you re-pasting).

Your global `~/.claude/CLAUDE.md` is already on your machine; Claude Code loads it automatically. Nothing to do for that one.

## Step 3 — Open the folder in VS Code
`File → Open Folder →` the `Network-Anomaly-Detector` folder. Open the Claude Code panel.

## Step 4 — Turn on Plan Mode
In Claude Code, press `Shift+Tab` until it says **Plan Mode** (so it proposes a plan before writing any files — you approve first).

## Step 5 — Paste this prompt into Claude Code

Copy everything between the lines and paste it as one message.

--------------------------------------------------------------------
Before doing anything, read these files and treat them as binding for the whole project:
- my global ~/.claude/CLAUDE.md
- docs/CLAUDE_CONTEXT.md  (my rules, stack, design system — non-negotiable)
- docs/PROJECT.md         (the agreed requirements and decisions)
- docs/PHASE-2-PLAN.md    (the phased build plan and per-phase test gates)
- docs/network-anomaly-detection-prompt.md (the detailed spec)

Then confirm in one short paragraph that you've read them and state: the product name, the frontend framework decision, the backend, the database, and the three hard rules you must never break. If any of those are unclear from the files, ask me — do not guess.

We are building NetSentinel. We are on BUILD-PHASE 0 ONLY — the foundation skeleton. Do NOT build any features (no packet capture, no ML, no AI, no auth, no styling). Phase 0's entire job is a running, empty-but-wired project pushed to GitHub.

Hard constraints (from my files, restate them back so I know you have them):
- NO Docker, ever. Manual config. Windows + VS Code terminal.
- Frontend: React 18 + Vite + Tailwind. Backend: Python + FastAPI. DB/Auth: Supabase. Everything free-tier only.
- Real data in the product; fixtures only in unit tests. Never commit secrets — .env is git-ignored from the first commit.

Phase 0 deliverables:
1. This folder structure (create only these — later folders come in their own phases, do not scaffold empty ones):
   Network-Anomaly-Detector/
   ├── README.md            (project pitch + "Phase 0 — foundation" status, honest)
   ├── LICENSE              (MIT)
   ├── SECURITY.md
   ├── CHANGELOG.md
   ├── .gitignore           (ignore .env, .venv, node_modules, __pycache__, dist, build)
   ├── .env.example         (every var we'll eventually need, with a comment + free-signup URL, placeholders only)
   ├── CLAUDE.md            (project-level: point Claude Code to docs/CLAUDE_CONTEXT.md, docs/PROJECT.md, docs/PHASE-2-PLAN.md so every future session auto-loads context; include the coding/security/testing rules distilled from those files)
   ├── docs/                (already contains the 8 files I added)
   ├── backend/
   │   ├── requirements.txt
   │   ├── .env             (git-ignored, copied from ../.env.example)
   │   └── app/
   │       ├── main.py      (FastAPI app + GET /api/health returning {"status":"ok"})
   │       └── config.py    (pydantic-settings loading env vars)
   └── frontend/            (Vite + React + Tailwind scaffold; a single page that calls /api/health and shows the result)
2. A Python virtual environment for the backend.
3. Frontend and backend wired so the frontend successfully calls the backend health endpoint.

Give me, in Plan Mode first:
- The exact list of files you will create.
- The exact Windows commands I'll run to set up and start both backend and frontend.
- Anywhere my spec is ambiguous or you'd choose differently, and why.

Then STOP and wait for my approval before writing anything.

Phase 0 test gate (we don't move on until all pass):
- uvicorn serves /api/health returning ok.
- The Vite app loads in the browser and shows the health result from the backend.
- The repo is pushed to GitHub with all base files present.
- .env is git-ignored and NOT on the remote.

One more thing throughout this project: teach me as you go — I'm learning while building. If you write something I couldn't explain in an interview, stop and explain it before moving on. Challenge my choices instead of agreeing by default.
--------------------------------------------------------------------

## Step 6 — After Claude Code finishes Phase 0
Run the commands it gives you, then check the test gate yourself:
- Backend running? Visit `http://localhost:8000/api/health` — you should see `{"status":"ok"}`.
- Frontend running? Visit `http://localhost:5173` — the page should show the health result (proving frontend↔backend talk).
- Repo pushed? Refresh your GitHub repo page — you should see the files, and `.env` should NOT be there (only `.env.example`).

If all four are green, come back here and say "Phase 0 done" — and I'll write the Phase 1 kickoff prompt (PCAP → flows → table).
