# MCP Connectors, Plugins & Skills — Reference & Decision Process

A reusable playbook for any future project: when to reach for a connector/plugin/skill, how to find one, and how to verify it's actually free before wiring it in. Pair this with the evaluation prompt at the bottom — paste that into a new project's first "what tooling do we need" conversation.

---

## The three things, and how they differ

| | Gives Claude... | Needs external access? | Cost model |
|---|---|---|---|
| **Connector (MCP server)** | Access to one external service/your data (Supabase, GitHub, Slack, Vercel...) | Yes — always talks to something outside the chat | Free/paid depends entirely on the *underlying service's* tier, not the connector itself |
| **Skill** | Reusable know-how for a recurring task, no external access | No | Always free — it's just instructions Claude follows |
| **Plugin** | A bundle of tools/commands/skills for one workflow (often several connectors + a skill together) | Sometimes (depends what's bundled) | Depends on what's inside |

**Key distinction to hold onto**: a connector's *existence* is always free (MCP itself has no cost) — what costs money, if anything, is the *service on the other end* (e.g., a paid Slack tier, a paid API plan). This is exactly the same free-tier-verification discipline used throughout ThreatHunter's build (Groq vs. Anthropic/OpenAI, Supabase's 2-project cap, IPInfo's free tier) — applied here to tooling instead of application dependencies.

---

## When to reach for each one, per project phase

- **Early planning / research** — connectors to web search, or a database connector once you have one, so Claude can check real current state instead of assuming.
- **Active development** — GitHub connector (or just `gh` CLI, often redundant with a connector — check which is already available before adding one), a database connector (Supabase, Postgres, etc.) for direct verification instead of manual dashboard round-trips — this was the single highest-value connector in ThreatHunter's build once it started working.
- **Testing phase** — Playwright MCP (official, Microsoft, free, no rate limits) — replaces scratch test scripts with native browser tools.
- **Security testing** — Burp Suite's official MCP, if you have Burp Community (free tier covers the core proxy/repeater workflow; Collaborator/out-of-band testing is Pro-gated).
- **Deployment** — Vercel MCP (official, free on Hobby tier) for deployments/logs/env vars through chat; Render doesn't currently have an official MCP as of this writing — verify before assuming one exists.
- **Ongoing team workflows** — this is where plugins fit: a bundle for something your team does repeatedly (e.g., "sales call prep," "PR review against our style guide") rather than a single connector.

---

## Where to actually find them

1. **Official directory**: `github.com/modelcontextprotocol/servers` — the canonical list, includes both official (company-maintained) and curated community servers. Start here.
2. **Registries/marketplaces**: Smithery (smithery.ai), mcp.so, Glama's directory (glama.ai/mcp/servers) — searchable, some with quality signals.
3. **Ask Claude Code directly** — it can search the MCP registry itself (the same way it found Playwright and confirmed the Supabase MCP worked in ThreatHunter) rather than you hunting manually. This is usually the fastest path.
4. **Platform-native connectors** — some (GitHub, Slack, Google Drive) are built into Claude's own Settings → Connectors, no external directory needed at all.

---

## The verification checklist — run this before wiring anything in

Same discipline as every dependency decision in ThreatHunter (Groq vs Anthropic, `render.yaml` env vars, the shadcn CLI chain). Before adding a connector, plugin, or skill:

1. **Is it actually free, or does it just look free?** Check the underlying service's real pricing page, not a blog summary — free tiers change, and "free" sometimes means "free trial" or "free up to a hidden limit." (This burned ThreatHunter once already — Supabase's 2-project cap wasn't obvious until it was hit.)
2. **Who maintains it?** Official (company-run) > well-known community (large user base, active commits) > random/unmaintained. An MCP server gets real tool access — treat an unfamiliar, unmaintained one with the same caution as an unfamiliar npm package with write access to your filesystem.
3. **Does it solve a real, current need — or a hypothetical future one?** Don't add a connector "just in case." Add it when a specific task is actually blocked or meaningfully slowed without it (the same bar Playwright cleared in ThreatHunter: it replaced an actual recurring pain point, not a theoretical one).
4. **Does something already cover this?** Check what's already connected/available before adding a duplicate (e.g., `gh` CLI already does most of what a GitHub connector would — redundant additions just add noise).
5. **What's the actual scope/permission level?** Prefer read-only or narrowly-scoped tokens over broad/write access, unless the task genuinely requires write (e.g., Supabase's MCP was deliberately kept read-only in ThreatHunter, with a service-role script handling writes separately).

---

## Evaluation prompt — paste into a new project

```
Before we go further, evaluate what MCP connectors, plugins, or skills would genuinely help THIS project — don't add anything speculative.

For each candidate you consider:
1. Confirm it's actually free (check the real current pricing of the underlying service, not an assumption) — this project has zero budget for paid tools/APIs, same constraint as everything else in it.
2. Confirm who maintains it (official vs. community) and whether it's actively maintained.
3. Confirm it solves a real, current bottleneck in this project's actual work — not a hypothetical future one.
4. Check whether something already available (a connector, CLI tool, or built-in capability) already covers the same need before recommending something new.
5. Recommend the minimum necessary scope/permission level (read-only where possible).

Search the MCP registry yourself rather than guessing at what exists. Give me your recommendation — what to add, why, and what NOT to add and why — before connecting or installing anything.
```

---

## Post-deployment: making sure no user, even by accident, can find a secret via dev tools

This applies to every future project, not just MCP tooling — worth keeping as a standing checklist for any deployment.

**The hard rule**: anything sent to the browser is visible, permanently, to anyone who opens dev tools — no minification, obfuscation, or clever hiding changes that. The only real defense is structural: **never send a secret to the browser in the first place.** "Hide it better" is not a real security strategy; "never transmit it" is.

**What this means in practice:**
- All real secrets (third-party API keys, database service-role keys, signing secrets) must live *only* in the backend's server-side environment — never in frontend env vars, never in client-side code, never in a cookie/localStorage value the frontend sets itself.
- Frontend-exposed env vars (e.g. Next.js's `NEXT_PUBLIC_*` prefix, Vite's `VITE_*`) are a *declaration that a value is safe to be public* — treat that prefix as a promise, and only ever put genuinely public values behind it (a Supabase anon key, a public API base URL). If something sensitive ends up with that prefix by mistake, it *will* ship to every visitor's browser.
- The frontend should only ever talk to your own backend, never directly to a third-party provider that needs a secret key — the backend proxies every external call, so the key never has a reason to exist client-side at all.
- For services like Supabase where a "public" key is unavoidable (the anon key), real protection comes from server-side policy (Row Level Security, backend auth checks) — not from hiding that key, since it's designed to be public.

**Verification checklist to run after any deployment:**
1. Open the live site, open dev tools → Network tab, use every feature (login, main actions, anything that hits an API).
2. Check every request/response body and every header for anything that shouldn't be public.
3. Check the page source and JS bundle (view-source, or the Sources tab) for any hardcoded secret.
4. Confirm: only values you've deliberately designated public (anon keys, public URLs) appear anywhere client-side — everything else should be completely absent, not just hard to find.
5. Ask your AI coding assistant to walk through *why* each secret is structurally unreachable from the client, not just confirm "looks fine" — a real explanation (e.g. "this key only exists in Render's server environment, the frontend has no code path that could reference it") is a stronger check than a visual scan.

---

## Notes carried over from ThreatHunter's build (what actually worked)

- Supabase MCP was set up mid-project specifically because manual dashboard back-and-forth had become a real, repeated cost (three+ rounds of "can you check X" before it was added) — that's the right trigger: a proven, felt pain point, not a hypothetical.
- It was scoped narrowly (read-only, project-pinned token, not org-wide) — worth replicating that instinct for any future database/service connector.
- Playwright MCP got recommended proactively once Testing/Deployment phases were approaching, because it was foreseeably useful there — worth reassessing tooling needs at each major phase transition, not just once at project start.
