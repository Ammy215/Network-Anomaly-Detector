# How Real Projects Get Built — Industry Workflow Reference

A guide to the actual professional software development lifecycle (SDLC) — what happens before, during, and after code — for someone learning by building with AI rather than through formal training. Grounded in ThreatHunter as a real, lived example throughout, since that project already followed most of this correctly.

**The core idea to internalize**: the gap between a "vibe coder" and an engineer isn't raw ability to produce code — AI has mostly closed that gap. The real gap is **process discipline**: designing before building, verifying before trusting, and documenting decisions so someone else (or future-you) can understand *why*, not just *what*. Everything below is about that discipline.

---

## The phases, in order

### 1. Discovery & Requirements

**What it is**: Before any design or code, figuring out what problem you're actually solving and for whom. In industry: talking to stakeholders/users, writing a problem statement, defining what "done" looks like.

**As a solo builder**: this is you writing down, in plain language, what the thing should do and why — before opening an editor. ThreatHunter's equivalent: the original prompt file (`threat-hunter-dashboard-prompt.md`) and `CLAUDE_CONTEXT.md` — a written spec of what the product is, before any architecture discussion happened.

**Deliverable**: a problem statement + a rough feature list, in writing.

---

### 2. Planning & Scoping

**What it is**: Turning requirements into an actual sequence of work — what gets built first, what's MVP vs. later, what's explicitly out of scope. In industry: sprints, tickets, a roadmap, story points.

**As a solo builder**: a phased plan with real boundaries per phase — not "build everything," but "Phase 1 does X, Phase 2 does Y, nothing more." ThreatHunter's equivalent: the 16-phase roadmap (Research → Architecture → Foundation → Auth → ... → Deployment), each with defined scope and an explicit test gate before moving on.

**Deliverable**: a phased plan, written down, with each phase's boundaries explicit (what's in, what's deliberately deferred).

---

### 3. System Design & Architecture

**What it is**: Before writing code, deciding how the pieces fit together — what talks to what, where data lives, what the major components are. This is the "whiteboard session" in a real team.

**Key artifacts, and free tools to actually make them:**
- **Architecture diagram** (boxes and arrows — frontend, backend, database, external services) — **Excalidraw** (excalidraw.com, free, hand-drawn style, genuinely good for this) or **draw.io** (diagrams.net, free, more formal)
- **Flowcharts** (decision logic, user flows) — same tools, or **Mermaid** syntax, which Claude can render directly for you inline in chat — just ask "diagram this as a flowchart" and it'll generate one live, no separate tool needed
- **Sequence diagrams** (who calls whom, in what order — e.g. "browser → backend → provider API → database") — Mermaid handles these too

**As a solo builder**: this is the conversation to have with Claude Code *before* touching code — "walk me through the architecture" the same way ThreatHunter's App Router and `@supabase/ssr` decisions got walked through, with real trade-offs stated, not just picked.

**Deliverable**: at least one real diagram (even hand-drawn/Excalidraw is fine) showing the major pieces and how data flows between them.

---

### 4. Database Design

**What it is**: Modeling your data's structure *before* writing queries — what entities exist, how they relate, what's normalized vs. denormalized. Getting this wrong early is expensive to fix later (ThreatHunter hit this directly: the redundant `investigation_id` FK, the missing `source_results` normalization layer, both caught and fixed in a dedicated Architecture phase specifically because it's cheaper to fix on paper than after data exists).

**Key artifact: an ERD (Entity-Relationship Diagram)** — boxes for each table, lines showing relationships (one-to-many, many-to-many), with key fields listed. Free tools: **dbdiagram.io** (write simple DSL, get a real ERD), or Mermaid's `erDiagram` syntax (same in-chat rendering).

**Key questions to answer on paper, before creating any table:**
- What are the core entities? (For ThreatHunter: investigations, indicators, users, CVEs...)
- How do they relate? (One investigation has many indicators; one indicator can appear in many investigations → many-to-many, needs a join table)
- What's the source of truth for a value that might be duplicated? (This is exactly the `normalizer.js`-vs-inline-service drift bug from ThreatHunter's Phase 7 — two places claiming to be the truth, silently diverging)

**Deliverable**: an ERD, even a simple one, before writing your first `CREATE TABLE`.

---

### 5. API Design

**What it is**: Deciding the *contract* between frontend and backend before building either — what endpoints exist, what they accept, what they return — so both sides can be built against an agreed shape instead of discovering mismatches later.

**In real teams**: this is often a formal OpenAPI/Swagger spec, written and agreed on before implementation starts (ThreatHunter actually has Swagger wired up via `config/swagger.cjs` — worth looking at as a real example of this artifact).

**As a solo builder**: doesn't need to be a full formal spec, but write down — even in a markdown table — each endpoint, its inputs, and its output shape, before building the frontend page that calls it. This is what would have caught the `routes/cve.js` route-ordering bug (dynamic route registered before static ones) earlier — a written contract makes "what does `/search` vs `/:cveId` actually do" explicit instead of implicit in code order.

**Deliverable**: a list of endpoints with method, path, request shape, response shape — even informal, written before the corresponding UI is built.

---

### 6. UI/UX Design

**What it is**: Designing the interface — layout, flow, visual language — before or alongside building it, rather than discovering the design while coding.

**Real-world tools**: **Figma** is the industry standard (free tier is generous — wireframes, mockups, even interactive prototypes). Lighter-weight: Excalidraw again for rough wireframes.

**The professional sequence, worth knowing even if you compress it as a solo builder:**
1. **Wireframes** — rough boxes, no color/style, just layout and content hierarchy
2. **Mockups** — actual visual design applied to the wireframe (colors, typography, real components)
3. **Design system** — the reusable rules (color palette, spacing scale, component library) that keep every screen consistent — this is exactly what ThreatHunter's Phase 11 Tier 1 built (`components/ui/*`, `04-design-system.md`)
4. **Prototype/build** — actual implementation

**As a solo builder**: at minimum, sketch a rough layout (even on paper or Excalidraw) before generating a page — it's much cheaper to redesign a sketch than a built React component.

**Deliverable**: at least a rough wireframe or written layout description before code, for any non-trivial page.

---

### 7. Development Practices

**What real teams do that a solo AI-assisted builder should adopt too:**

- **Branching strategy** — feature branches off `main`, merged via pull request, rather than committing straight to `main`. Even solo, this protects you: if something breaks, `main` stays stable and you can abandon a branch cleanly.
- **Commit hygiene** — small, meaningful commits with clear messages (`feat:`, `fix:`, `security:`, `test:` prefixes — exactly what ThreatHunter's build used throughout), not one giant "stuff" commit at the end.
- **Code review** — in a team, another human reviews every change before merge. Solo, the equivalent is making Claude Code *explain* what it built and why before you accept it — which is the exact discipline this whole ThreatHunter conversation modeled: asking for reasoning, not just output.
- **`.gitignore` and secrets hygiene from day one** — decided *before* the first commit, not retrofitted (ThreatHunter got this right from Phase 0).

---

### 8. Testing Strategy

**What it is**: A layered approach, known as the "test pyramid" — many fast, cheap unit tests at the base; fewer, slower integration tests in the middle; a small number of full end-to-end tests at the top.

- **Unit tests** — test one function in isolation, with fixture/fake data (this is *correctly* where mock data belongs, even in a "no fake data" project — ThreatHunter's own testing-split correction covered this exactly)
- **Integration tests** — test multiple pieces together (e.g. a route + real database), often with external services mocked at the boundary
- **E2E tests** — test the whole real system, real browser, real data, closest to how a user actually experiences it

**Deliverable**: at minimum, unit tests for your core business logic (the equivalent of ThreatHunter's `threat_scorer.ts` tests) and one real end-to-end test of your main user flow.

---

### 9. CI/CD & Deployment

**What it is**: Automating test-and-deploy so shipping isn't a manual, error-prone ritual. Covered in depth in `systems-design-vocabulary-reference.md` — the practical version: a GitHub Actions workflow that runs your test suite on every push, and only deploys if it passes.

**Deliverable**: at minimum, a documented, repeatable deployment process (ThreatHunter's `docs/deployment/WALKTHROUGH.md` is a real example of this) — ideally automated later.

---

### 10. Monitoring & Maintenance

**What it is**: Once live, watching for real problems — error rates, performance, security alerts — instead of only finding out something's broken when a user complains. In industry: tools like Sentry (error tracking), Datadog/Grafana (metrics), uptime monitors.

**As a solo builder, minimum viable version**: a health-check endpoint (ThreatHunter has one, `/api/health`), periodic manual checks after deploy, and a habit of checking logs after any change — not full observability tooling, but the same *instinct*.

---

## A reusable project-kickoff prompt

Use this at the very start of a new project, before any code — mirrors the discipline that made ThreatHunter's build actually work, more rigorously than the "act as X" prompt templates it's inspired by, because it forces design artifacts to exist *before* implementation, not alongside it.

```
Before writing any code, walk me through this project the way a senior engineer would scope it:

1. Restate the problem and core requirements back to me — confirm we agree on what this actually needs to do before anything else.
2. Propose a phased build plan — what's genuinely MVP, what's explicitly deferred, with a real test/verification gate at the end of each phase (not "looks done," something checkable).
3. Design the system architecture — major components, how data flows between them. Give me this as a description I can also ask you to render as a Mermaid diagram.
4. Design the database schema — core entities, relationships, and specifically call out anything that could become a normalization problem later (duplicate sources of truth, redundant foreign keys).
5. Sketch the API contract — endpoints, methods, request/response shapes — before building any frontend page that depends on them.
6. Flag every real architectural decision (framework choice, database choice, auth strategy, etc.) as something to walk through with trade-offs, not something to silently pick — the same way you'd explain App Router vs Pages Router, not just choose one.
7. Only after all of the above is written down and I've confirmed it, start Phase 1.

Hold yourself to "verified, not assumed" throughout — test claims for real, tell me honestly when something doesn't work rather than rounding up to "done."
```

---

## How this maps to what already happened in ThreatHunter

If you want to see every one of these phases in a real, complete example, you already have one — walk back through this exact conversation:

| SDLC phase | ThreatHunter's real equivalent |
|---|---|
| Discovery & Requirements | `threat-hunter-dashboard-prompt.md`, `CLAUDE_CONTEXT.md` |
| Planning & Scoping | The 16-phase roadmap |
| Architecture | Phase 2 (indicator normalization design, schema fixes) |
| Database Design | Phase 2 + the `schema.sql` family of files |
| API Design | `routes/*.ts` + Swagger docs |
| UI/UX Design | Phase 11's tiered design-system plan |
| Development Practices | Every phase's commit discipline, the `verify-and-ship` skill |
| Testing | Phase 14 (89 tests, real test pyramid) |
| CI/CD & Deployment | Phase 16, `WALKTHROUGH.md` |
| Monitoring | `/api/health`, the config-validation startup checks |

You didn't just build *a* project — you followed close to the real professional workflow, phase by phase, whether or not it was labeled that way at the time. That's worth knowing going into an interview: you're not "a vibe coder who got lucky," you're someone who can point to a real project and explain the process behind every layer of it.
