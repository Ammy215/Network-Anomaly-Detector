# Deployment walkthrough — from a clean clone to a live URL

Every step below is literal and copy-pasteable. "What you should see" is
given after each step so you can tell immediately if something went wrong.
Written for redeploying from scratch, not just for this one time.

**What gets deployed:** the dashboard, PCAP upload/analysis, ML scoring, AI
investigation, threat-intel enrichment, auth, and RBAC — all free, all
public. **What doesn't:** live packet capture, because free hosting doesn't
grant raw-socket access inside a shared container. That's not something
this project failed to solve — see `docs/PROJECT.md` §8. Live capture stays
a local-only feature you run and demo from your own machine.

---

## 0. Prerequisites

- A GitHub account with this repo pushed to it.
- A Supabase project already set up (you have this from Phase 0 — same
  project, no changes needed, just its existing URL/keys).
- Real API keys for: Groq (LLM), AbuseIPDB, OTX, IPInfo, VirusTotal, NVD
  (all from `backend/.env` — you already have these from earlier phases).

---

## 1. Backend — Render

### 1.1 Create a Render account
Go to https://render.com, sign up (GitHub OAuth is the fastest path — it
also gives Render read access to your repos for the next step).
**You should see:** the Render dashboard, empty, with a "New +" button
top-right.

### 1.2 Create the Web Service
1. Click **New +** → **Web Service**.
2. Connect your GitHub account if not already connected, then select this
   repo.
3. **Name:** `netsentinel-backend` (or anything — this becomes part of
   your `.onrender.com` URL).
4. **Region:** closest to you.
5. **Branch:** `main`.
6. **Root Directory:** leave **blank** — the build context needs to be the
   repo root (not `backend/`), because the Docker build reads both
   `backend/` and `docs/`.
7. **Runtime:** Render should auto-detect **Docker** once it sees
   `backend/Dockerfile`. If it offers a runtime dropdown, pick **Docker**
   explicitly.
8. **Dockerfile Path:** `backend/Dockerfile` (set this explicitly if
   Render doesn't find it automatically from the root).
9. **Instance Type:** **Free**.
10. Do **not** click Create yet — add environment variables first (next
    step), or add them right after and let Render redeploy once.

**You should see:** a service creation form with the repo connected and
Docker detected as the runtime.

### 1.3 Environment variables
In the same creation form (or the service's **Environment** tab afterward),
add every one of these as a key/value pair — paste real values, never
placeholder text:

| Key | Value |
|---|---|
| `ENVIRONMENT` | `production` |
| `BACKEND_CORS_ORIGINS` | *(leave as `http://localhost:5173` for now — you'll update this in step 3 once the Vercel URL exists)* |
| `SUPABASE_URL` | your Supabase project URL |
| `SUPABASE_ANON_KEY` | your Supabase anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | your Supabase service-role key |
| `ABUSEIPDB_API_KEY` | your key |
| `OTX_API_KEY` | your key |
| `IPINFO_API_KEY` | your key |
| `VIRUSTOTAL_API_KEY` | your key |
| `NVD_API_KEY` | your key |
| `LLM_API_KEY` | your Groq key |

Leave `VECTOR_DB_URL`, `MINI_SIEM_WEBHOOK_URL`, `THREATHUNTER_ENDPOINT_URL`
unset — they stay disabled exactly as they do locally. Leave `TSHARK_PATH`
unset too — the container finds `tshark` on its own `PATH` after the
Dockerfile's `apt-get install`.

**You should see:** a list of env vars in Render's Environment tab, values
masked after saving.

### 1.4 Deploy
Click **Create Web Service** (or **Deploy** if you already created it).
Render pulls the repo, builds the Docker image, and starts the container.
**This first build takes several minutes** — the image installs `tshark`,
every Python dependency, and bakes in the RAG corpus (downloads a MITRE
ATT&CK bundle during the build). Watch the **Logs** tab.

**You should see, in order:** `apt-get` installing `tshark`, `pip install`
output, then a line like `MITRE techniques: 10 techniques, 13 chunks` (the
RAG ingestion step), then `Uvicorn running on http://0.0.0.0:$PORT`. The
service status badge turns green ("Live").

### 1.5 Verify the backend is actually up
Visit `https://<your-service-name>.onrender.com/api/health` in a browser.
**You should see:** `{"status":"ok"}`.

If the service was idle, this first request may take 30s–1min (free-tier
cold start) — that's expected, not a failure.

Copy this backend URL — you need it for the frontend in the next section.

---

## 2. Frontend — Vercel

### 2.1 Create a Vercel account
Go to https://vercel.com, sign up with GitHub.
**You should see:** the Vercel dashboard with an "Add New..." → "Project"
option.

### 2.2 Import the project
1. Click **Add New...** → **Project**.
2. Select this repo from the list (authorize Vercel's GitHub App if asked).
3. **Root Directory:** click Edit, select `frontend`.
4. **Framework Preset:** Vercel should auto-detect **Vite**. If not, select
   it manually.
5. **Build Command:** `vite build` (Vercel's Vite preset fills this in
   automatically — leave it as the default).
6. **Output Directory:** `dist` (also auto-filled by the Vite preset).

**You should see:** a project configuration screen with `frontend` as the
root directory and Vite detected.

### 2.3 Environment variables
Before deploying, add these three (Vercel's import screen has an
Environment Variables section, or add them afterward in
**Settings → Environment Variables** and redeploy):

| Key | Value |
|---|---|
| `VITE_SUPABASE_URL` | your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | your Supabase anon key |
| `VITE_API_URL` | your Render backend URL from step 1.5, e.g. `https://netsentinel-backend.onrender.com` |

**You should see:** three variables listed, each scoped to at least the
Production environment.

### 2.4 Deploy
Click **Deploy**. Vercel runs `npm install` then `vite build`.
**You should see:** a build log ending in something like
`Build Completed`, then a "Congratulations" screen with a live URL
(`https://<project-name>.vercel.app`).

---

## 3. Wire the two together — CORS

Now that you have the real Vercel URL:
1. Back in Render, open your backend service → **Environment** tab.
2. Edit `BACKEND_CORS_ORIGINS` to your actual Vercel URL, e.g.
   `https://netsentinel.vercel.app` (comma-separate more than one origin
   if needed — no trailing slash).
3. Save — Render redeploys the service automatically on env var changes.

**You should see:** the service redeploy (Logs tab shows a fresh build/
restart), status returns to "Live."

---

## 4. End-to-end verification

1. Visit your Vercel URL. **You should see:** the NetSentinel login screen.
2. Sign up with a real email. **You should see:** a new account created,
   landing on the dashboard with **viewer** permissions (read-only).
3. Have an admin (via the Supabase dashboard's `user_profiles` table, or
   the app's admin panel if you already have an admin account) promote
   your account to `analyst` if you want to upload/investigate.
4. Upload a real PCAP. **You should see:** flows appear, scored.
5. Open a flagged flow → **Investigate**. **You should see:** a real AI
   investigation result after several seconds (LLM call in progress),
   with citations and a MITRE mapping where applicable.
6. Open browser dev tools → Network tab, repeat steps 2-5, and run the
   secret-exposure checklist from
   `docs/mcp-connectors-plugins-skills-reference.md` — confirm nothing but
   the Supabase anon key and public URLs are visible anywhere client-side.

---

## Redeploying after a code change

- **Backend:** push to `main` — Render auto-deploys on push (confirm
  **Auto-Deploy** is on in the service's Settings; it's on by default).
- **Frontend:** push to `main` — Vercel auto-deploys the same way.
- **CI:** every push also runs `.github/workflows/test.yml` (pytest, LLM
  calls excluded by `pytest.ini`'s default marker filter) — check the
  Actions tab on GitHub for a green check before assuming a deploy is safe.

## If the shipped ML model changes

The active model artifact
(`backend/models/isolation_forest_behavioural_only_381419f9.joblib`) is
committed to the repo specifically so it survives Render's lack of
persistent disk. If you ever retrain and promote a new model version:
commit the new artifact under the same `backend/models/` exception pattern
in `.gitignore`, remove the old one from git if you no longer need it
served, and push — Render will bake the new file into the next image build.
