# NetSentinel — Project Brief & Requirements (Phase 1: Discovery)

> **Repo:** https://github.com/Ammy215/Network-Anomaly-Detector.git
> **Status:** Phase 1 — Discovery & Requirements. Nothing is built yet. This document is the agreed understanding of *what we're building and why*, before any architecture or code.
> **How to use this file:** This is the project's north-star doc. In Claude Code, keep it in the repo (e.g. `docs/PROJECT.md`) and reference it from the project `CLAUDE.md`. It complements — does not replace — your global `~/.claude/CLAUDE.md` and your `CLAUDE_CONTEXT.md`.

---

## 1. The one-sentence version

NetSentinel watches network traffic, learns what "normal" looks like for that network, flags the traffic that *doesn't* look normal, and then uses AI (grounded in real security references, not guesses) to explain *why* it's abnormal and what an analyst should check next.

It is a **detection and investigation** tool. It is not an attack tool, and it never claims certainty it doesn't have.

---

## 2. How this actually works (plain English — read this first)

You said you have zero mental model for how this thing detects anything. Here's the whole idea, no jargon, in the order the data actually moves.

**Step 1 — Get the traffic.**
Every conversation between two machines on a network is made of *packets* (tiny individual messages). We get these one of two ways: you upload a capture file (a `.pcap` — think of it as a "recording" of network traffic, the kind Wireshark makes), or, later and only on your own lab machine, we watch live traffic off a network interface. **We build the upload path first** because it's safe, repeatable, and doesn't require special permissions.

**Step 2 — Turn packets into flows.**
Thousands of raw packets are hard to reason about. So we group them into *flows*: one flow = "machine A talked to machine B, on this port, using this protocol, for this long, sending this many packets and bytes." This is the single most important concept in the whole project. A flow is a *summary of a relationship*, not a single message. Real enterprise tools (the Darktrace/Cisco class) work on flows for exactly this reason — it scales, and it avoids storing sensitive raw content.

**Step 3 — Describe each flow with numbers (features).**
A machine-learning model can't look at "machine A talked to machine B." It needs numbers. So for each flow we compute *features*: packets per second, average packet size, how many different ports this host touched, how regular the timing is, the ratio of connection-attempts to completed-connections, and so on. These numbers are the fingerprint of a flow's *behavior*.

**Step 4 — Learn what normal looks like.**
Here's the clever part, and the reason this isn't just a rules list: we don't tell the model what an attack looks like. We can't — nobody has a clean labeled list of "all attacks." Instead we show it a lot of *normal* traffic, and it builds a statistical sense of the normal region. This is called **unsupervised anomaly detection**. The two models we use (Isolation Forest and One-Class SVM) are just two different math approaches to the same question: "is this new flow far away from the normal cluster or inside it?"

**Step 5 — Score the abnormal ones.**
Every new flow gets an *anomaly score*. High score = "this behaves unlike the normal traffic I learned." Crucially — and this is a discipline we enforce everywhere in the UI and AI copy — **a high anomaly score is not the same as "this is an attack."** It means "this is unusual, a human should look." A backup job running at 3am is unusual too. We keep three ideas separate on purpose: *baseline* (normal), *anomaly* (unusual), *threat* (actually bad). Conflating them is how bad security tools cry wolf.

**Step 6 — Enrich and explain.**
For flows that look genuinely suspicious (not every flow — that would spam free APIs and leak data), we look up the external IP's reputation (is it a known bad actor?), and we run an **AI explanation pipeline**. The AI doesn't guess from memory — it *retrieves* real reference text (MITRE ATT&CK technique descriptions, protocol docs) and explains the anomaly grounded in that text, citing what it used. This is called **RAG (Retrieval-Augmented Generation)**, and it's the difference between "the AI thinks this is a port scan" and "this matches MITRE T1046 Network Service Discovery because [specific evidence], per [cited source]."

**Step 7 — Show the analyst, get their verdict.**
The dashboard shows the anomaly, the evidence, the AI's explanation, and lets *you* mark it: True Positive / False Positive / Benign / Unknown. That feedback is stored and later used to tune thresholds — but the system never silently retrains itself off your clicks without a validation step.

That's the whole machine. Capture → flows → features → learn normal → score → enrich → explain → analyst decides. Every arrow is something you'll build and be able to explain in an interview.

---

## 3. What it must do (functional requirements)

1. **Ingest traffic** — accept an authorized `.pcap`/`.pcapng` upload (Mode A, built first). Later, optional authorized live capture on your own lab interface (Mode B), with an explicit warning and interface selection.
2. **Assemble flows** — group packets into bidirectional flows with a clean, documented schema.
3. **Extract features** — compute a documented, justified feature set per flow (not "every feature we can think of").
4. **Baseline + detect** — learn a normal baseline, score new flows with Isolation Forest and One-Class SVM, and compare the two models honestly on real metrics.
5. **Score with transparency** — produce a normalized anomaly score (0–100) plus the specific features/deviations that caused it. Never a bare "suspicious" with no reason.
6. **Enrich selectively** — only flagged indicators get sent to external threat-intel APIs; extract/normalize IPs/domains first.
7. **Explain with AI + RAG** — grounded, cited, hedged explanations mapped to MITRE ATT&CK *where the evidence supports it*.
8. **Investigate** — an investigation view that reads as a coherent story: what happened, why it's unusual, the evidence, the intel, the AI assessment, related events, your notes.
9. **Analyst feedback loop** — mark verdicts; feed threshold tuning; never auto-retrain blindly.
10. **Visualize** — an interactive network graph, a flow/anomaly timeline, a model-comparison dashboard, and (in live mode) real-time metrics. No fake live data, ever.
11. **Auth + roles** — login/signup, and role separation (admin vs. analyst vs. viewer) — see §7.
12. **Audit** — every meaningful action logged with who/when/IP.

---

## 4. What it must NOT do / be (non-functional + hard boundaries)

- **Free only.** Every tool, API, database, and host must be genuinely free-tier, verified against *current* real pricing — not assumed. Zero budget, no exceptions.
- **No Docker.** Per your standing rule: everything configured and run manually, so you understand each moving part. (This is a deliberate correction from the earlier blueprint, which used docker-compose — we are dropping that.)
- **Windows-native workflow.** All run commands target Windows + VS Code integrated terminal.
- **Ethical boundary is hard.** Your own machines, your own lab, or explicitly authorized networks only. No stealth interception of other people's traffic, no malware, no credential-theft features, no capturing arbitrary public traffic. Prefer flow metadata over raw packet payloads; don't persist payloads by default.
- **Language discipline.** Detection language is always evidence-based and hedged: "behavior contains indicators consistent with X," never "AI detected malware." This applies to scoring, UI copy, and AI output alike.
- **Deep, not bloated.** Explicitly out of scope for this project (not corners cut, just genuinely later/other projects): a full MLOps platform, Kubernetes, microservices, an autoencoder before the simple models are understood, and any dependency that can't answer "what problem does it solve here?"

---

## 5. "Won't this tool compromise my own machine?" (your explicit worry — answered)

Good instinct to ask. Three real risks and how we handle each:

1. **Packet capture needs elevated privileges.** Live capture (Mode B) requires admin/root-equivalent rights and can see sensitive data on your network. Mitigation: build and rely on **PCAP upload (Mode A) first**; make live capture opt-in, interface-explicit, warned, and lab-only. You lose nothing by developing entirely in upload mode.
2. **The AI layer is an attack surface.** If a *retrieved document* contains text like "ignore previous instructions," that's a prompt-injection attempt (indirect injection). We treat all retrieved/ingested content as untrusted data, never as instructions, and we build real prompt-injection test cases. AI tools (MCP) are least-privilege, read-only where possible, permission-scoped, validated, logged — and **never** get arbitrary shell access.
3. **Uploaded files are hostile input.** A `.pcap` is attacker-controllable. We validate extension/MIME/size, never execute uploaded content, parse defensively (one malformed packet must not crash analysis), and store uploads safely.

The tool operates on *observations*; it never takes irreversible action on its own, and it has no code path that would let a captured/retrieved input control your machine. That's the design guarantee.

---

## 6. Databases — the decision (preview, finalized in Phase 3/4)

You asked which databases. Here's the current thinking, each earning its place. We'll confirm in the Architecture/DB-Design phases, but the shape is:

- **One relational database (system of record)** — stores hosts, flows, features, anomaly scores, alerts, investigations, users, audit logs. This is structured, related data with real integrity needs, so a relational DB (PostgreSQL-family) is correct. **Supabase** is the likely pick because its free tier also gives us **Auth** (login/signup/roles) in the same place, which removes a whole category of work — and you already know Supabase from ThreatHunter. Alternative considered: plain local PostgreSQL (more manual, no built-in auth). We'll justify the final choice with trade-offs, not just pick.
- **One vector database (for RAG)** — stores the embedded MITRE/protocol reference text so the AI can retrieve by *meaning*. Candidates: **Chroma** (simplest, runs locally, zero setup) vs **Qdrant** (more capable, free local mode). We'll pick one and explain collections/vectors/metadata/similarity rather than treating it as a magic "AI database."
- **Redis — only if justified.** Not by default. We add it *only* if we hit a real need (caching repeated intel lookups, or coordinating live-mode real-time updates). Per your systems-design reference, adding it speculatively would be over-engineering. We'll flag explicitly if/when it earns its place.

No MongoDB here (your log analyzer used it; this project's data is relational, so Postgres is the better fit — a deliberate, explainable choice).

---

## 7. Admin & auth — what it is, how you'll use it (your explicit question)

**What "admin" means here:** the highest-privilege role. NetSentinel has three roles:
- **admin** — full access: manage users, view audit logs, manage settings/API keys, see all investigations.
- **analyst** — do the actual work: upload PCAPs, investigate anomalies, run enrichment, write notes.
- **viewer** — read-only.

**How you get an admin account (the practical answer):** with Supabase Auth, you sign up through the app's normal signup form with your own email, and then — for the *first* admin — you promote that account to admin once, directly in the Supabase dashboard (a one-line change to your user's role, or a tiny seed script we run once). After that, admins can invite/promote others from inside the app. So: **your email, your chosen password, signup like a normal user, promoted to admin once at setup.** There's no secret hardcoded admin password (that would be a security hole). We'll document the exact one-time promotion step in the setup guide.

**Do you even need auth?** For a portfolio tool that handles network data and has an admin panel, yes — and it's a strong interview talking point (RBAC, JWT/session handling, audit logging). You already built this pattern in ThreatHunter, so we're reusing hard-won knowledge, not learning it cold.

---

## 8. Deployment — is it even deployable, and free? (your explicit question)

**Honest answer: partly, and yes-for-the-part-that-matters.**

- **The dashboard + backend API + PCAP-analysis path: fully deployable, free.** Frontend on Vercel (free), backend on Render or Fly.io free tier, database + auth on Supabase free tier, vector DB self-hosted alongside the backend or on a free tier. This is the part an interviewer clicks — it works as a live link.
- **Live packet capture: not deployable on free hosting**, because free-tier containers don't grant raw-socket access. That's not a NetSentinel limitation, it's how shared hosting works. Mitigation (and it's a perfectly respectable one): the hosted demo runs in **replay/upload mode** against recorded PCAPs; you demo live capture locally via screen-share or a local tunnel during interviews. We state this plainly in the README — it's an accurate engineering constraint, not a failure.

So the deployment story is: "live public demo of the full analysis + AI + dashboard, with live-capture shown locally." That's a strong, honest answer. Exact step-by-step deployment (every small step, plus "what you should see after") is a **Phase 9 (CI/CD & Deployment)** deliverable — we'll write it when we get there, not now.

---

## 9. API keys you'll need (all free tiers — your explicit constraint)

None are needed to *start* (Phase 1–2 are pure capture/flow/feature work, no keys). As phases arrive:

| Key | Used for | Phase it's first needed | Free? |
|---|---|---|---|
| AbuseIPDB | IP reputation on flagged IPs | Threat-intel phase | Yes (1000/day) — you have this |
| AlienVault OTX | Threat pulses / IOC correlation | Threat-intel phase | Yes — you have this |
| IPInfo | Geolocation for the map | Threat-intel phase | Yes (50k/mo) — you have this |
| VirusTotal | Hash/domain/URL context | Threat-intel phase | Yes (500/day) — you have this |
| NIST NVD | CVE context for enrichment | Threat-intel phase | Yes (free, no cost; key just raises rate limit) |
| An LLM API key | The AI explanation + RAG generation | AI phase | Must be a genuinely free option — **we verify this before committing to a provider** (free tiers shift; we check current limits at that phase, per your mcp/tooling reference discipline) |
| Supabase keys | DB + auth | Foundation phase | Yes (free tier) |

Every key lives server-side only, in `.env` (never committed), never shipped to the browser. `.env.example` documents every variable with a comment and its free-signup URL.

---

## 10. Testing philosophy (your explicit, repeated concern)

You want rigorous testing at every phase and a final pass. Here's the reconciliation of an apparent contradiction in your rules first: **"no mock data" applies to the product** (the app never shows fake results or dummy datasets to a user). **Fixture/dummy data is correct and expected inside unit tests** — that's where a known, controlled input with a known expected output belongs. Both your CLAUDE_CONTEXT rule and "test with dummy data" are right; they're just about different layers.

The layered approach (built per-phase, not bolted on at the end):
- **Unit tests** (fixtures) — feature extraction, flow assembly, scoring, parsers, detection rules give known outputs for known inputs.
- **ML tests** — preprocessing consistency, feature-schema stability, model load/inference, threshold behavior, and explicit guards against data leakage (train/test, feature, temporal).
- **Integration tests** — the real PCAP pipeline, the database, the AI pipeline, with external APIs mocked at the boundary.
- **E2E test** — upload a real PCAP → detect a real anomaly → open investigation → get AI explanation → record feedback, against the real running system.
- **AI evaluation** — not "sounds good": a small RAG eval set (query → expected concepts → retrieved docs → score), and agent/tool tests (right tool chosen, fails safely, no hallucinated tool results, prompt-injection resisted).
- **Adversarial security testing** — Burp Suite / OWASP methodology against *your own running app*: auth, IDOR, input validation, SSRF, rate limiting, file-upload handling. Plus the bridge exercise: generate authorized Burp/Nmap traffic and see whether NetSentinel itself flags it.
- **Final pass before deployment** — full regression on both live and recorded data, accuracy sanity-check on known cases, and the post-deployment secret-exposure hardening checklist (nothing sensitive reachable from the browser).

Every phase has a concrete **test gate**: a checkable result, not "looks done," before the next phase starts.

---

## 11. Git & GitHub workflow (your explicit requirement)

- **Repo:** https://github.com/Ammy215/Network-Anomaly-Detector.git — created empty (no README, no .gitignore, no license added at creation, as you did). **Claude Code generates all of those itself** on first commit: `README.md`, `.gitignore`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `.env.example`.
- **Commit everything, continuously.** Small, meaningful conventional commits (`feat:`, `fix:`, `security:`, `test:`, `docs:`, `chore:`) at the end of every working session — never one giant dump. Push at the end of every session so the repo is always up to date and your contribution history reflects the real work.
- **Branch per phase/feature**, merged into `main`; `main` stays working.
- **Never commit secrets** — `.env` is git-ignored from the very first commit, not retrofitted.
- **`.gitignore`** excludes `.env`, virtualenvs, `node_modules`, `.next`, and generated PCAP/dataset artifacts (keep the *scripts* that make them, not the large files) — with a small allow-listed folder of reference PCAPs for reproducible tests.

---

## 12. How we build it (process — driven by your reference files)

We follow the phase structure from `how-real-projects-get-built.md`, and consult the other three references at the right moments:

1. **Discovery & Requirements** ← *this document.*
2. **Planning & Scoping** — a phased build plan with explicit in/out scope and a test gate per phase.
3. **System Architecture** — components + data flow, rendered as a diagram; every infra choice checked against `systems-design-vocabulary-reference.md` (and I'll tell you explicitly when I'm deliberately *not* using something, e.g. Redis or a queue, and why).
4. **Database Design** — an ERD, with normalization traps called out before any `CREATE TABLE`.
5. **API Design** — the endpoint contract (method, path, request, response) before any frontend that depends on it.
6. **UI/UX** — only here do we open `frontend-resources-reference.md` and evaluate those tools against this project's actual needs; composition, contrast, typography first, motion per-element not uniform.
7. **Development** — teach → plan → implement → test → review → document, one feature at a time.
8. **Testing** — the layered strategy in §10.
9. **CI/CD & Deployment** — the free deployment path, every manual step documented, plus the post-deploy secret-exposure checklist.
10. **Monitoring** — a health-check endpoint and a habit of checking logs after every change.

At each major phase transition we consult `mcp-connectors-plugins-skills-reference.md` to check whether a connector/plugin/skill removes a *real* bottleneck — verifying it's free, maintained, and actually needed before adding anything.

**Ground rules that hold across all of it:** free-tier only (verified, not assumed) · verify don't assume (test claims for real, say honestly when something doesn't work) · explain trade-offs before deciding · design before code, function before polish, security code tested adversarially not just reviewed.

---

## 13. What it can and can't catch — adversarial robustness (your core concern)

You care most about this: does it actually catch the crafty things attackers do? Honest answer, because pretending otherwise is exactly the "rounding up to done" your rules forbid.

**The fundamental truth:** anomaly detection catches *deviation from normal*. So it's strong against attackers who look unusual, and weak against attackers who deliberately look normal. **No anomaly detector catches everything — any tool that claims to is lying, and saying so out loud is a strong interview answer, not a weakness.**

**What NetSentinel can catch, and how:**
- **Fast/noisy port scans** — many SYN-only flows, high port entropy. Easy.
- **Slow "low-and-slow" scans** — an attacker spreading a scan over hours to stay quiet. We handle this with wider time windows and *host-level* aggregation features, so the scan still accumulates even when no single minute looks bad.
- **Distributed scans** (many source IPs, one target) — we aggregate at the destination/service level, not just per-flow, so the pattern shows up even when each source looks innocent alone.
- **Beaconing / command-and-control** — malware "phones home" on a regular clock; humans don't. An inter-arrival-time *regularity* feature catches this rhythm.
- **DNS tunneling / exfiltration** — abnormal query length, character randomness, and volume.
- **Encrypted/obfuscated payloads** — irrelevant to us, and that's a genuine strength: we score on flow *metadata*, not payload content, so encryption doesn't blind us the way it blinds signature-based tools.
- **Standard evasion tricks** (fragmentation, etc.) — tshark/PyShark reassembly handles the common cases.

**What it cannot fully catch (stated plainly):**
- A patient attacker who *perfectly mimics your baseline traffic* — living-off-the-land, blending into normal volumes and destinations. That's the hard limit of anomaly detection, for everyone.
- The real defense against that is **defense in depth**, and it's built into this project's design: NetSentinel is **one layer**, combined with known-bad threat intel (§9), correlation with your Mini SIEM's log-based detections, and a human analyst making the final call. Real SOCs never rely on anomaly detection alone — and NetSentinel's architecture reflects that on purpose.

**The requirement this creates:** the detection layer must be *tested adversarially*, not just reviewed — in the lab we generate evasive traffic (a slow scan, a distributed scan, a beaconing pattern) and verify NetSentinel flags it, or we honestly document the miss and tune for it. Thresholds must be tunable so you can trade sensitivity against false positives per environment. This is a Phase-8 (Testing) and detection-engineering deliverable, but it's a *requirement* now so it never quietly gets dropped.

## 14. Clean slate & no-dead-code discipline (your "remove all garbage" requirement)

You asked repeatedly to delete deprecated/unused/broken files and keep the project clean. Two parts:

- **Right now there's nothing to delete** — this is a brand-new empty repo. You start from zero, so there's no legacy cruft, no half-working files, no dead code to remove. The earlier Docker-based blueprint does **not** carry over.
- **It becomes a standing per-phase rule:** every phase ends with *only working, needed code committed* — no commented-out dead blocks, no unused dependencies in `requirements.txt`/`package.json`, no abandoned files, no "temporary" scripts left lying around. If something stops being used, it's deleted in the same commit, not left to rot. Claude Code enforces this at each phase's review step, and you can spot-check it in the diff before every commit.

## 15. Full technology stack & rationale (one line of "why" per choice)

Every dependency has to answer: what problem does it solve, why here, what's the alternative. Settled choices first, then two decisions that are **yours to make**.

**Settled:**
- **Backend: Python + FastAPI** — this project is packet-processing- and ML-heavy, and FastAPI is async-native (capture, ML inference, and LLM calls run concurrently). Alternative: Flask (you know it) — rejected because async isn't bolted on in FastAPI, it's structural. You're also learning FastAPI, which is a goal.
- **Capture/parsing: Scapy + PyShark (tshark)** — Scapy for sniffing and safe lab traffic crafting; PyShark for authoritative deep protocol parsing of PCAPs. Different jobs, not redundant. Alternative: raw sockets (you did that in HoneyShield) — rejected here because reinventing protocol dissection wastes time this project should spend on ML/AI.
- **ML: scikit-learn (Isolation Forest + One-Class SVM)** — the right tools for unsupervised anomaly detection, lightweight, explainable. Alternative: PyTorch autoencoder — deliberately deferred until the simple models are understood; adding it now would be "advanced for its own sake."
- **Relational DB + Auth: Supabase (Postgres)** — structured, related data with integrity needs, *plus* free built-in auth/RBAC in the same place. Alternative: local Postgres (more manual, no auth) — rejected because auth-from-scratch is work you already did in ThreatHunter and don't need to repeat.
- **Vector DB: Chroma (leaning) vs Qdrant** — for RAG retrieval by meaning. Chroma is simplest and runs locally with zero setup; Qdrant is more capable. We'll pick one in Phase 5 and justify it, understanding collections/vectors/metadata/similarity rather than treating it as magic.
- **Redis: not included unless it earns its place** — per your systems-design reference, adding it speculatively is over-engineering. Added only if repeated intel caching or live-mode coordination becomes a real need.

**Decision #1 — frontend framework: LOCKED to React 18 + Vite.** Your `CLAUDE_CONTEXT.md` standardizes on it, it's familiar ground, and this is a dashboard behind auth (SSR/SEO irrelevant; secrets are backend-proxied), so Next.js's extra machinery would be cost without benefit here. Next.js was the alternative (from the NetSentinel prompt); rejected for this project for the reasons above.

**Your decision #2 — LLM provider (must be genuinely free).** OpenAI (in your context file) has no real free tier, so it's out for a zero-budget project. Free candidates to verify at the AI phase: **Groq** (fast, generous free tier), **Google AI Studio / Gemini** (free tier). We confirm current limits before committing — free tiers shift.

## 16. The ML pipeline (explicit)

raw packets → validation → flow assembly → cleaning → feature extraction → normalization → train/validation/test split → train baseline on *normal* traffic → Isolation Forest + One-Class SVM → anomaly score → threshold → versioned model artifact → inference on new flows.

Teaching points enforced throughout: guard against every leakage type (train/test, feature, normalization, temporal); version every model (id, algorithm, dataset, features, params, seed, metrics, threshold, created_at) and never silently replace one; keep a small experiment framework comparing models on precision/recall/F1, false-positive/negative rate, and inference time; and if labels are unavailable, say so plainly rather than fabricating an accuracy number. Legitimate research datasets (CIC-IDS2017, UNSW-NB15, TON_IoT) are candidates for baseline/comparison — licensing and feature/label meaning checked before training on any.

## 17. The AI + RAG pipeline (explicit)

**RAG ingest (offline):** curated reference docs (MITRE ATT&CK, protocol/network-security docs, your own detection notes) → loading → chunking (with overlap) → metadata → embeddings → vector DB.
**Investigation (per flagged anomaly):** anomaly + evidence → gather context → selective threat-intel enrichment → RAG retrieval of relevant reference chunks → LLM analysis → **structured, hedged, cited output** (`summary`, `observations`, `evidence`, `hypotheses`, `confidence`, `recommended_actions`, `related_techniques`) → analyst panel.

LangChain is used only where it adds real value (loaders, splitters, retrievers, structured output), not to wrap every function. LangGraph is introduced *after* the basic pipeline works, for one small stateful workflow (analyze → retrieve → enrich → evaluate evidence → explain), teaching nodes/edges/state/conditional routing. Agents/subagents: a *small* number of focused, permission-scoped, logged tools (`lookup_ip`, `search_attack_technique`, `retrieve_security_document`, `inspect_flow`, `compare_baseline`) — to learn specialization and delegation, not to build twenty agents. The AI never makes an irreversible security decision on its own.

## 18. Learning roadmaps (the three the prompt asked for)

**Claude Code / MCP / subagents (in order):** CLAUDE.md discipline → planning before features → context management → codebase exploration (trace data flow) → refactoring → debugging (understand before fixing) → code review → security review → ML review (challenge my leakage/eval/threshold choices). Then MCP done *properly*: client vs server, tools vs resources, permissions, transport, least-privilege, read-only where possible, no shell access ever. Then subagents: specialization, delegation, context boundaries, result passing, failure handling. You keep a Claude Code learning journal (what worked, what failed, where it hallucinated, what you corrected). You should be able to explain the difference between plain API vs tool-calling vs MCP vs agent vs subagent vs RAG vs vector DB.

**Cybersecurity:** TCP/IP + protocols (TCP/UDP/ICMP/DNS/HTTP/ARP/DHCP) → packets vs flows → reconnaissance/scanning/beaconing/brute-force/DNS-anomaly concepts → baselining → detection engineering → IOC enrichment → threat hunting → MITRE ATT&CK mapping (with evidence) → adversarial testing of your own detector (§13). Wireshark stays a *human validation* tool the detector points you toward, not something the system replaces.

**UI/UX:** (opened fully in Phase 6, with `frontend-resources-reference.md`) SOC-console feel, not neon-hacker cliché → React Flow network graph, D3 where justified, Framer Motion → composition/contrast/typography first, motion per-element not uniform → the key surfaces (network graph, flow/anomaly timeline, live view, AI investigation panel, model dashboard, anomaly card, investigation workspace, threat-hunting queries, correlation timeline).

## 19. Integrations with your existing projects (both, loosely coupled)

Design toward optional, clean-API integration — never tight coupling:
- **Mini SIEM** — NetSentinel emits normalized security events → Mini SIEM correlates → alert. Plus the reverse correlation for fused incidents (§13).
- **ThreatHunter** — an anomaly's extracted IOC (IP/domain/hash) → sent to the ThreatHunter dashboard → intel lookup → result returned. This is the integration I dropped earlier and am restoring: it's a strong "my projects form one platform" story for interviews.

## 20. Design system (locked — from your CLAUDE_CONTEXT.md)

Not re-decided per project. Applied in Phase 6:
- **Backgrounds:** `#050d1a` (page), `#0a1628` (cards), `#0f1e35` (elevated), `#1a2d4a` (borders).
- **Accents:** cyan `#00d4ff` (primary), green `#00ff88` (safe/low), amber `#ffb800` (medium), red `#ff3366` (high/critical, + pulse on critical), purple `#8b5cf6` (AI features).
- **Type:** JetBrains Mono for all IPs/hashes/CVE IDs/domains/ports; Inter for UI (700 for metric numbers, 400–500 for labels/nav). No text below 12px.
- **Verdict colors** map to the accent scale above; UNKNOWN = gray `#64748b`.

## 21. Interview demo scenario & first milestone

**The one reproducible demo to build toward (the prompt's target):** authorized local lab → generate normal traffic → run a controlled Nmap scan → capture → analyze the PCAP → detection flags abnormal scanning → anomaly score with visible reasons → source IP extracted → threat-intel enrichment → RAG retrieves relevant knowledge → AI investigation explains the evidence, hedged → MITRE ATT&CK mapping shown → analyst validates the time window in Wireshark → analyst marks the verdict → event stored → optionally consumed by Mini SIEM. Everything downstream is built so this demo works end to end.

**First milestone only (what Phase 2 will scope as the first real build target):** the PCAP-upload path working end to end at its simplest — upload a `.pcap` → assemble flows → store them → view them in a basic table. No ML, no AI, no polish yet. That single vertical slice proves the spine works before anything hangs off it.

## 22. Note on the earlier blueprint

The large `nad-blueprint.md` I produced before is **superseded on stack and infrastructure** (it used Docker, ChromaDB/Postgres/Redis, and a Next.js-only assumption). Its *conceptual* explanations (how RAG works, what Isolation Forest does, packet-vs-flow) are still fine as background reading. **This `PROJECT.md` is the source of truth.** Where they disagree, this file wins.

## 23. Performance & efficiency (your "speed with accuracy / quality and quantity")

The rule: **measure before optimizing** — no guessing at bottlenecks, no premature optimization. Once there's code, we measure PCAP processing time, packets/flows per second, model inference latency, API latency, RAG retrieval latency, AI response latency, and frontend render time. Structural choices that protect speed *without* costing accuracy: large PCAPs are streamed/chunked and processed in a background job so the HTTP request never blocks or loads the whole file into memory; repeated threat-intel and RAG lookups are cached; model artifacts load once, not per request. Accuracy is never silently traded for speed — any such trade-off is measured and written down. Concrete latency/throughput targets are set at measurement time (Phase 8 testing / Phase 11 performance), not invented now.

## 24. Coverage register — every source you gave me, and where it's handled

So "did you consider everything?" is checkable, not a promise. Three buckets: **in this doc**, **logged & scheduled for a later phase** (correct per the phased approach — not dropped), and **needs you**.

| Source | Key contents | Status |
|---|---|---|
| `CLAUDE_CONTEXT.md` — rules | No Docker, real-data-in-product, Windows, one-repo, phase+test-gate, mentor tone | ✅ In doc §4, §10, §11, §12 |
| `CLAUDE_CONTEXT.md` — design system | Hex tokens, JetBrains Mono/Inter, no <12px | ✅ In doc §20 |
| `CLAUDE_CONTEXT.md` — stack | FastAPI backend; React (Vite) frontend | ✅ §15 (frontend flagged as your decision) |
| `CLAUDE_CONTEXT.md` — API keys | AbuseIPDB/OTX/IPInfo/VT/NVD | ✅ §9 |
| `CLAUDE_CONTEXT.md` — "how I like prompts generated" | Paste-ready Claude Code prompt format | 🕒 Applied when I generate the Claude Code kickoff prompt (post-Phase-2) |
| `CLAUDE_CONTEXT.md` — session triggers, common commands, run/stop | "generate a prompt" etc.; uvicorn/npm commands; `--break-system-packages`, Windows venv | 🕒 Setup/run guide, built when there's something to run |
| `network-anomaly-detection-prompt.md` — problem, modes, ethics, packets-vs-flows | Core spec | ✅ §2, §3, §4, §5 |
| — ML: features, IF/OCSVM, leakage, registry, datasets | | ✅ §16 |
| — AI: RAG, LangChain/LangGraph, agents/subagents, MCP, structured output | | ✅ §17, §18 |
| — Security: Burp/OWASP/Nmap/Wireshark/Scapy, prompt-injection, privacy | | ✅ §5, §10 |
| — UI surfaces & pages | Network graph, timeline, AI panel, model dashboard, etc. | 🕒 §18 lists them; full design is Phase 6 |
| — False-positive workflow & model lifecycle | Mark TP/FP/Benign, no auto-retrain | ✅ §3, §10 |
| — Integrations (Mini SIEM + ThreatHunter) | Loosely coupled | ✅ §19 |
| — Repo files & engineering-notes structure | README/LICENSE/SECURITY/CHANGELOG; `/engineering-notes/01–12`; `.env` var list | 🕒 §11 covers repo files; numbered notes + env list built at repo-setup/dev phases |
| — Final demo scenario, completion bar, interview/resume | | ✅ §21 (demo); interview/resume is the end-of-project deliverable |
| — "Discovery only, then stop" (12 items) | Its own response spec | ✅ §1–21 now cover all 12; stopping at gate |
| `how-real-projects-get-built.md` | SDLC phase structure | ✅ §12 (the shape of the whole build) |
| `systems-design-vocabulary-reference.md` | Judge over-engineering | ✅ §6, §15 (Redis/Docker/K8s/microservices/MLOps explicitly declined) |
| `mcp-connectors-plugins-skills-reference.md` | Verify free/maintained/needed; post-deploy secret checklist | ✅ §10, §12 (consulted at each phase transition) |
| `frontend-resources-reference.md` | Motion/shadcn/color tools | 🕒 §18 — opened in Phase 6 (UI) only, as the file itself instructs |
| Your message — performance, "remove garbage", "won't hack me", admin, deploy-free, testing, commit-everything | | ✅ §5, §7, §8, §10, §11, §13, §14, §23 |
| Your message — put these files into Claude Code / VS Code | Mechanical step | 🕒 See below |
| Global `~/.claude/CLAUDE.md` | Unknown contents | ✅ Resolved — the Claude Code kickoff prompt will instruct it to read & honor the global file locally; no paste needed |

**The "put this into Claude Code" step (so it's not lost):** once you approve, in your repo you'll keep `PROJECT.md` (this file) and `network-anomaly-detection-prompt.md` in a `docs/` folder, and the project `CLAUDE.md` (which Claude Code writes in the Foundation phase) will point to both so Claude Code always has them in context. You don't need to do anything manual now.

## 25. The gate

This document is the Phase 1 deliverable, and §24 accounts for all six files, your prompts, and your instructions. **Both open decisions are now resolved** — frontend is React 18 + Vite (§15), and the global `~/.claude/CLAUDE.md` will be honored via the Claude Code kickoff prompt. No-Docker/Supabase direction, the admin model, and the deployment reality stand as written.

Phase 1 is complete. The Phase 2 deliverable — the phased build plan with a test gate per phase — is in the companion `ROADMAP.md`. Still no code.
