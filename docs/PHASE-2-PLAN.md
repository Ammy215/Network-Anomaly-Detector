# NetSentinel — Phase 2: The Phased Build Plan

> **Prerequisite:** `PROJECT.md` (Phase 1 — Discovery) approved.
> **What this is:** the whole build broken into ordered phases, each with explicit in-scope / deferred boundaries, a concrete deliverable, and a **test gate** — a *checkable* pass condition that must be green before the next phase starts. This is the "Planning & Scoping" deliverable from `how-real-projects-get-built.md`.
> **What this is NOT:** code, architecture diagrams, ERDs, or API contracts. Those are Phases in their own right (they come inside Foundation/Detection). This is the map.

---

## Guiding rules (carried from Phase 1, true for every phase below)

- **No Docker.** Manual config, Windows-native, VS Code terminal.
- **Free-tier only**, verified against real current pricing — never assumed.
- **Real data in the product; fixtures only inside unit tests.**
- **Teach → plan → implement → test → review → document** every substantial feature.
- **Commit per session, push per session**, conventional commits, `.env` git-ignored from commit #1.
- **A phase is done when its test gate is green — not when it "looks done."**
- **Security-sensitive code is tested adversarially, not just reviewed.**

## Why this order (the dependency logic)

Each phase produces something the next one needs. You can't tune a model before you have features; you can't build features before you have flows; you can't assemble flows before you can ingest a PCAP. AI/RAG comes after detection because it *explains* detections — it needs real anomalies to explain. UI comes after there's real data to show (no fake live data, ever). Auth and deployment come late because you harden and ship a thing that already works, rather than building scaffolding around nothing.

---

# STAGE A — Foundation

## Phase 0 — Repo & skeleton
- **Goal:** a running, empty-but-wired project pushed to GitHub.
- **In scope:** init repo at your URL; Claude Code generates `README.md`, `.gitignore`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `.env.example`; FastAPI skeleton with a `/api/health` route; Vite + React + Tailwind skeleton; Supabase project created; frontend and backend talking to each other; the Claude Code kickoff prompt (which tells Claude Code to read your global `~/.claude/CLAUDE.md`, `CLAUDE_CONTEXT.md`, and `docs/PROJECT.md`).
- **Deferred:** every feature. This is plumbing only.
- **Deliverable:** the repo, first commit(s) pushed.
- **Test gate:** `uvicorn` serves `/api/health` returning OK; the Vite app loads in the browser and successfully calls `/api/health`; repo is on GitHub with all base files; `.env` is git-ignored and absent from the remote.

## Phase 1 — First milestone: PCAP → flows → table
- **Goal:** the spine works end to end at its simplest.
- **In scope:** `POST /api/pcap/upload` with validation (extension, MIME where possible, size cap; never execute the file); parse with PyShark; assemble packets into bidirectional flows (5-tuple, close on FIN/RST/timeout); store flows in Supabase; a plain frontend table listing flows.
- **Deferred:** ML, scoring, AI, enrichment, styling, auth.
- **Deliverable:** upload a real `.pcap`, see correct flows.
- **Test gate:** a known real `.pcap` produces the expected flows in the table (spot-checked against Wireshark); a deliberately malformed/oversized/wrong-type file is rejected cleanly and does **not** crash the server; one bad packet doesn't abort the whole analysis.

---

# STAGE B — Detection Core

## Phase 2 — Feature engineering & baseline
- **Goal:** turn flows into the numeric fingerprints the models will use, and define "normal."
- **In scope:** compute a *documented, justified* feature set per flow (packets/sec, bytes/sec, avg packet size, inter-arrival mean/std, unique dst ports, port entropy, SYN ratio, etc. — selected, not all-of-them); normalization; build a baseline profile of normal behavior; keep baseline / anomaly / threat conceptually separate.
- **Deferred:** the models themselves.
- **Deliverable:** a feature table per flow + a documented feature-selection rationale.
- **Test gate:** unit tests — a known fixture PCAP produces the exact expected feature vector (regression-locked); feature schema is stable and documented; normalization is fit on training data only (no leakage).

## Phase 3 — ML detection (Isolation Forest + One-Class SVM)
- **Goal:** score flows for how far they are from normal, with two models compared honestly.
- **In scope:** train Isolation Forest and One-Class SVM on normal baseline; anomaly scoring; threshold selection; a small experiment framework comparing the two on precision/recall/F1, false-positive/negative rate, and inference time; model versioning (id, algorithm, dataset, features, seed, params, metrics, threshold, created_at); explicit guards against train/test, feature, normalization, and temporal leakage.
- **Deferred:** the optional autoencoder (only after these two are understood); auto-retraining.
- **Deliverable:** two trained, versioned models + a comparison table.
- **Test gate:** both models train and score; the comparison table is real (with an honest "unlabeled — no accuracy claim" note where labels are absent); thresholds are documented; a leakage self-check passes; inference latency is recorded.

## Phase 4 — Score transparency & false-positive workflow
- **Goal:** every anomaly explains *why*, and the analyst can judge it.
- **In scope:** normalized 0–100 anomaly score shown with the specific features/deviations that caused it (never a bare "suspicious"); analyst marks each anomaly True Positive / False Positive / Benign / Unknown with optional reason; feedback stored for later threshold tuning.
- **Deferred:** auto-retraining from feedback (needs a validation step, later); AI narrative.
- **Deliverable:** an anomaly view with reasons + a working verdict/feedback loop.
- **Test gate:** every displayed anomaly lists its contributing features; verdicts persist to the DB; the system never silently retrains from a click.

---

# STAGE C — Intelligence Layer

## Phase 5 — Threat-intel enrichment (selective)
- **Goal:** add external reputation context — only where warranted.
- **In scope:** extract/normalize indicators (IP/domain) from flagged anomalies; enrich **only flagged** indicators via AbuseIPDB / OTX / IPInfo / VirusTotal / NVD; cache results; all keys server-side only.
- **Deferred:** enriching every internal IP (privacy + rate-limit waste — explicitly not done).
- **Deliverable:** enrichment shown on flagged anomalies.
- **Test gate:** only flagged indicators are sent externally (verified); keys never appear in any browser request/response/bundle; an API failure degrades gracefully (no crash, no infinite retry).

## Phase 6 — RAG knowledge base
- **Goal:** a real retrieval system so the AI cites facts instead of guessing.
- **In scope:** curate reference docs (MITRE ATT&CK, protocol/security docs, your own notes); load → chunk (with overlap) → metadata → embed → store in the vector DB (Chroma, decision confirmed here with rationale); build a retriever; build a small RAG eval set (query → expected concepts → retrieved → score) measuring precision@k / recall@k / relevance.
- **Deferred:** the generation/LLM step (next phase).
- **Deliverable:** a queryable knowledge base + recorded retrieval-quality scores.
- **Test gate:** known queries return the expected relevant chunks; eval scores are recorded in `docs/`; retrieved content is treated as untrusted data (never as instructions).

## Phase 7 — AI investigation pipeline
- **Goal:** grounded, hedged, cited explanations of anomalies — safely.
- **In scope:** LLM analysis grounded in RAG context + flow evidence, producing structured output (`summary`, `observations`, `evidence`, `hypotheses`, `confidence`, `recommended_actions`, `related_techniques`) with hedged language and MITRE mapping *only where evidence supports it*; then LangGraph for one small stateful workflow (analyze → retrieve → enrich → evaluate evidence → explain); then a *few* permission-scoped, logged tools/subagents; real prompt-injection test cases (including indirect via retrieved docs). Free LLM provider chosen and verified here (Groq / Gemini free tier).
- **Deferred:** large agent swarms; any AI ability to take irreversible action.
- **Deliverable:** a working AI investigation panel per anomaly.
- **Test gate:** structured output validates against schema every time; every claim traces to cited evidence or flow data; indirect prompt-injection test cases are resisted; tools fail safely and are logged; the AI takes no autonomous security action.

---

# STAGE D — Experience Layer

## Phase 8 — Frontend build-out (the UI phase)
- **Goal:** a SOC-console-grade dashboard on real data. This is where `frontend-resources-reference.md` opens.
- **In scope:** apply the locked design system (§20 of PROJECT.md); build the key surfaces — network graph (React Flow), flow/anomaly timeline, anomaly cards, investigation workspace, model dashboard, AI panel; composition/contrast/typography first; motion per-element (Framer Motion), not uniform; skeleton loading; keyboard shortcuts/command palette where they earn it.
- **Deferred:** the live-monitoring real-time view (needs Mode B, Phase 10).
- **Deliverable:** a polished, navigable dashboard wired to the real backend.
- **Test gate:** every page shows real backend data (zero fake/placeholder data); WCAG-AA contrast holds; it's responsive; nothing is a static mockup.

## Phase 9 — Auth, RBAC, admin & audit
- **Goal:** real access control and accountability.
- **In scope:** Supabase Auth (signup/login, email verification); three roles (admin/analyst/viewer) enforced server-side; admin panel (users, audit logs, settings); audit logging of every meaningful action with who/when/IP; documented one-time admin promotion (your email → promoted once via Supabase).
- **Deferred:** advanced org/multi-tenant features (out of scope for this project).
- **Deliverable:** working auth + role separation + admin panel + audit trail.
- **Test gate:** role restrictions are enforced on the **server**, not just hidden in the UI (verified by trying a forbidden call directly); audit logs populate; a viewer cannot perform analyst/admin actions; admin promotion works as documented.

---

# STAGE E — Extend, Harden & Ship

## Phase 10 — Live capture mode (Mode B, optional, lab-only)
- **Goal:** authorized live monitoring, safely.
- **In scope:** explicit interface selection; a clear warning about sensitive-data exposure; opt-in only; background capture producing the *same* flow schema as upload; the live-monitoring real-time view (packets/flows/sec, bandwidth, anomalies/min) via WebSocket or SSE (choice justified).
- **Deferred / hard boundary:** never on by default; never captures arbitrary public traffic; lab/authorized networks only.
- **Deliverable:** working live mode in your lab.
- **Test gate:** live mode is opt-in and warned; produces schema-identical flows; real-time view shows real data only; capturing requires an explicit interface choice.

## Phase 11 — Integrations (Mini SIEM + ThreatHunter)
- **Goal:** make the projects one platform, loosely coupled.
- **In scope:** emit normalized events to Mini SIEM (→ correlation → alert); hand an anomaly's extracted IOC to ThreatHunter (→ intel lookup → result back); clean API/event schemas; each integration optional and independently togglable.
- **Deferred:** tight coupling of any kind.
- **Deliverable:** both integrations working and optional.
- **Test gate:** each integration works when enabled and the app runs fine when it's disabled; schemas are documented; no hard dependency created.

## Phase 12 — Adversarial security testing
- **Goal:** attack your own app and your own detector, on purpose.
- **In scope:** Burp/OWASP methodology against the running app (auth, authorization/IDOR, input validation, SSRF, rate limiting, file-upload handling); the bridge exercise (authorized Burp/Nmap traffic → does NetSentinel flag it as unusual?); adversarial evasion tests against the detector (slow scan, distributed scan, beaconing per §13 of PROJECT.md).
- **Deferred:** nothing — this is a gate, not a nice-to-have.
- **Deliverable:** a written security-testing report with findings + fixes.
- **Test gate:** every finding is documented and fixed (or risk-accepted with reason); evasion cases are either detected or honestly documented as known misses with the mitigation plan.

## Phase 13 — Performance pass
- **Goal:** speed with accuracy, measured (per §23 of PROJECT.md).
- **In scope:** measure PCAP processing, flows/sec, inference latency, API/RAG/AI latency, frontend render; large PCAPs streamed/chunked in a background job (request never blocks/OOMs); cache repeated lookups; load model artifacts once; optimize only measured bottlenecks; set targets.
- **Deferred:** speculative optimization of anything not measured.
- **Deliverable:** recorded measurements + targets + any justified optimizations.
- **Test gate:** measurements exist for each metric; a large PCAP processes without blocking or running out of memory; no accuracy was traded for speed without it being written down.

## Phase 14 — Deployment (free)
- **Goal:** a live, free, public demo — the part interviewers click.
- **In scope:** frontend → Vercel (free); backend → Render/Fly free tier; DB/auth → Supabase; vector DB self-hosted with the backend or free tier; every manual step documented (each small step, plus "what you should see after each"); the honest replay-mode note (live capture is local-only because free hosting has no raw-socket access); the post-deployment secret-exposure hardening checklist from `mcp-connectors-plugins-skills-reference.md`.
- **Deferred:** hosting live packet capture (not possible on free tier — documented, not hidden).
- **Deliverable:** a working live URL + a deployment walkthrough doc.
- **Test gate:** the live URL runs the demo scenario end to end; the secret-exposure checklist passes (nothing sensitive reachable from the browser — verified in dev tools); the walkthrough reproduces the deploy from scratch.

## Phase 15 — Final verification & portfolio package
- **Goal:** the "one final, final check" you asked for.
- **In scope:** full regression on both live and fixture data; accuracy sanity-check on known cases; run the one reproducible interview demo (§21 of PROJECT.md) start to finish; generate interview questions grounded in what was actually built; 3–4 honest resume bullets (no fabricated users/traffic/accuracy numbers); a portfolio package (architecture diagram, threat-flow diagram, screenshots, short demo video, model comparison, RAG architecture, security-testing report).
- **Deliverable:** a demonstrably working system + interview/resume assets.
- **Test gate:** the full demo runs clean with no errors; every config is connected and returns real, accurate results; nothing in the resume/portfolio is fabricated; all prior phase gates are still green (regression).

---

## Testing, restated (because you asked for it at every stage)

Two layers, both mandatory:
1. **Per-phase gates** — the checkable condition at the end of each phase above. No phase advances until its gate is green.
2. **Dedicated hardening phases** — Phase 12 (adversarial security), Phase 13 (performance), and Phase 15 (final full regression on live + dummy data). Bugs found late get fixed and re-gated, not shipped.

## The gate for Phase 2

This is the plan. Nothing is built yet. If the phase order, boundaries, or gates look wrong, say so now — reordering a plan is free, reordering built code is not.

**On approval:** we begin **Phase 0**, and the first thing I produce is the paste-ready Claude Code kickoff prompt (in your preferred format from `CLAUDE_CONTEXT.md`: folder structure, files, exact commands, phase build order, test step, `.env` template) — which will also instruct Claude Code to read your global `~/.claude/CLAUDE.md`, `CLAUDE_CONTEXT.md`, and `docs/PROJECT.md` before it does anything.
