# NetSentinel — Project Instructions

Read these before doing anything in this repo — they are binding for the whole project:

- [`docs/CLAUDE_CONTEXT.md`](docs/CLAUDE_CONTEXT.md) — author's stack, skill level, design system
- [`docs/PROJECT.md`](docs/PROJECT.md) — agreed requirements and decisions (source of truth when in conflict with anything else)
- [`docs/PHASE-2-PLAN.md`](docs/PHASE-2-PLAN.md) — the phased build plan and per-phase test gates

## Hard rules (never break these)

1. **No Docker, ever.** Manual configuration only, Windows + VS Code terminal.
2. **Free-tier only, verified not assumed.** Check current pricing/limits before committing to any API or host.
3. **Real data in the product; fixtures only inside unit tests.** The app never shows fake/mock/placeholder results to a user. `.env` is git-ignored from commit #1 — never commit secrets.

## Process

- **One phase at a time.** Each phase in `docs/PHASE-2-PLAN.md` has an explicit scope and a checkable test gate. Don't start the next phase until the current one's gate is green.
- **Teach → plan → implement → test → review → document** for every substantial feature. If something wouldn't be explainable in an interview, stop and explain it before moving on.
- **No dead code.** Every phase commits only working, needed code — no commented-out blocks, no unused dependencies, no scaffolded-but-empty folders for future phases.
- **Security-sensitive code is tested adversarially**, not just reviewed (see Phase 12 in `docs/PHASE-2-PLAN.md`).
- **Detection language is hedged, never absolute** — "behavior contains indicators consistent with X," never "AI detected malware."
- External threat-intel/API keys live server-side only, never shipped to the browser.

## Commits

Conventional commits (`feat:`, `fix:`, `security:`, `test:`, `docs:`, `chore:`), small and meaningful, pushed at the end of each working session.
