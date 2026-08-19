# Systems Design & Infrastructure Vocabulary — Reference

A glossary of common systems/infra terms, with plain-English explanations and honest guidance on when each is actually worth using vs. when it's over-engineering for a project's actual scale. Companion to `frontend-resources-reference.md` and `mcp-connectors-plugins-skills-reference.md`.

**The one rule that applies to all of it**: almost every term below solves a *scale* problem (many servers, many teams, huge data volumes, massive request rates). Reaching for one by default, before a project actually has that problem, doesn't make it "more enterprise" — it makes it harder to reason about and more likely to break. The stronger move is understanding *why* a tool exists well enough to correctly explain not using it yet.

---

## Deployment & infrastructure

**Kubernetes** — Orchestrates many containers across many servers: auto-restarts crashed ones, scales up under load, spreads traffic. Needed once you have a *fleet* of services to manage, not for a single backend service on a PaaS like Render.

**CI/CD (Continuous Integration / Continuous Deployment)** — Automatically running tests/builds on every push (CI), and automatically deploying if they pass (CD), instead of doing it by hand. Broadly useful on **any** project with a repo — catches mistakes before they reach production. Free via GitHub Actions.

**Microservices** — Splitting one app into many small, independently-deployed services instead of one unified backend. Solves an *organizational* scaling problem (many teams shipping independently) more than a technical one — usually the wrong default for a solo or small-team project.

**Serverless compute** (e.g. AWS Lambda, Vercel Functions) — Code that runs only on-demand, billed per invocation, no server sitting idle. Great for bursty/intermittent workloads; wrong fit for anything needing persistent in-memory state (e.g. rate-limit counters) across requests.

**CDN (Content Delivery Network)** — Caches static content (JS, CSS, images) on servers physically close to each visitor for fast load times worldwide. Modern hosts (Vercel, Netlify) give you this automatically — nothing to build.

**Reverse proxy** — Sits in front of your app server, handles incoming requests first: SSL termination, routing, load balancing, caching. Nginx is the classic standalone example. PaaS platforms (Render, Vercel) already run one for you.

**Forward proxy** — Sits in front of *clients*, routing their outgoing requests (anonymity, filtering, bypassing network restrictions). Different direction from a reverse proxy — mostly a corporate-network/VPN concept, rarely relevant to how you deploy an app.

**API Gateway** — A single entry point that routes requests to different backend *services*, often centralizing auth/rate-limiting. Only useful once you have multiple services to route between.

**Sidecar** — A helper container deployed alongside a main app container to handle one job (logging, proxying) without touching the app's own code. A Kubernetes-ecosystem pattern; not applicable without Kubernetes.

**Load balancer** — Spreads incoming traffic across multiple running copies of a server so no single instance is overwhelmed. Relevant once you'd run more than one instance of your backend simultaneously.

---

## AWS specifically — the classic three-way split

**Amazon EC2** — Rent a virtual server, full control over the OS and what runs on it, billed continuously whether busy or idle. The "always-on machine you manage" model.

**AWS Lambda** — Serverless functions; upload code, AWS runs it only when triggered, billed per execution. The "pay only when it runs" model.

**Amazon RDS** — A managed relational database (Postgres, MySQL) — AWS handles backups, patching, scaling. The "don't babysit your own database server" model.

The pattern: EC2 = rent a computer, Lambda = rent a function call, RDS = rent a managed database. Modern platforms (Vercel, Render, Supabase) offer the same three models through simpler, often free-tier-friendly interfaces without touching raw AWS.

---

## Data & storage

**ACID** — Four guarantees a database transaction makes: Atomicity, Consistency, Isolation, Durability — an operation either fully happens or fully doesn't, and isn't corrupted by something else happening concurrently. Relevant when choosing a database: matters a lot for financial records, bookings, case-management data; matters less for logs/analytics events. Postgres (and by extension Supabase) is fully ACID-compliant — often the reason to pick it over a NoSQL store for structured, relational data.

**S3 (Amazon S3 / "S3 bucket")** — Cloud storage for **files** (images, PDFs, backups) as opposed to structured rows/columns in a database. A "bucket" is the container; objects inside it have unique keys/paths. Needed once an app has to persist user uploads or generated files long-term — a server's own disk is temporary and shouldn't be relied on for this.

**DynamoDB** — AWS's NoSQL key-value/document database, built for massive scale and simple access patterns. Wrong shape for relational data (things with real relationships between records) — Postgres/RDS is the better fit there.

**Elasticsearch** — A search engine built for fast full-text search and log analysis across huge datasets. Relevant once basic database indexing/filtering isn't fast or flexible enough (e.g. fuzzy search across huge text volumes).

---

## Security & networking

**Encryption** — Scrambling data so only someone with the right key can read it. "In transit" = HTTPS, protecting data moving over the network (non-negotiable for any deployed project, usually automatic on modern hosts). "At rest" = the stored data itself is encrypted (often automatic with managed databases).

**Firewall** — Rules controlling what network traffic is allowed in/out of a server. Usually handled at the platform level on a PaaS — not something you configure by hand there.

**Rate limiting** — Capping how many requests one client can make in a time window (e.g. 100 requests/15 min), responding with HTTP 429 past the limit. Prevents abuse and protects against runaway costs from third-party API calls. Broadly useful on any public-facing API.

**Circuit breaker** — Stops calling a failing external service after repeated failures (with a cooldown before retrying), instead of hammering it forever. Useful on any app that leans on third-party APIs — a lighter version of this is just "gracefully handle a provider failure without retrying infinitely."

**SFTP** — Secure File Transfer Protocol, for moving files to/from a server securely. Relevant for bulk file-transfer workflows; not something most web apps need directly.

---

## Communication patterns

**WebSockets** — A persistent, two-way connection between browser and server, so the server can push data instantly the moment something changes, instead of the browser having to keep asking. Good for chat, live notifications, collaborative editing, real-time dashboards.

**Polling** — Repeatedly asking a server "anything new?" on an interval, instead of a persistent connection. Simpler than WebSockets, often good enough — many apps (e.g. via React Query's `staleTime`/refetch pattern) use this successfully instead of building real-time infrastructure.

**Message queues** (general concept) — A buffer between two systems: one produces tasks, another consumes them asynchronously, decoupled from the request/response cycle. Needed once an app has real background-job/"do this later" needs.

**RabbitMQ** — A specific, traditional message-queue system. Overkill until there's a real background-processing need; a simple cron job is often sufficient at small scale.

**Kafka** — A message-queue-like system built for very high-throughput event streaming (millions of events), used at large-scale companies. Meaningful over-engineering for anything below that scale — naming it as a planned addition for a small project can read as a red flag rather than a strength.

---

## ML

**TensorFlow** — Google's machine learning framework for building/training neural networks. Overkill for problems that need to be *explainable* (a deterministic weighted-scoring formula is often the better, more interview-defensible choice) or that don't need deep learning at all. For lighter/classical ML (e.g. RandomForest), scikit-learn is the more appropriate, lower-overhead starting point.

---

## Dev workflow

**Cherry-picking** — Taking one specific Git commit from one branch and applying it to another, without merging everything else on that branch. `git cherry-pick <commit-hash>`. Useful any time a single fix needs to move to a different branch without dragging along unfinished work.

---

## Performance vocabulary (terms, not tools)

**Throughput** — How much work a system handles per unit time (e.g. requests/second).

**Latency** — How long a single request takes, start to finish. Distinct from throughput, and sometimes in tension with it (optimizing one can hurt the other).
