# Frontend Design & Animation Resources — Reference Doc

A reusable reference for evaluating and wiring in these 9 resources on any future project. Pair with the evaluation prompt (separate, for pasting into a new Claude Code session) — this file is the *background knowledge*, that prompt is the *action trigger*.

---

## The dependency map (read this first)

These 9 resources aren't independent — several share prerequisites, and understanding the chain avoids surprise scope creep:

```
Tailwind CSS (base requirement for all of them)
   │
   ├── Motion (motion.dev) ── standalone animation engine
   │      │
   │      └── Motion Primitives ── pre-built components ON TOP of Motion
   │
   ├── shadcn CLI + components.json + Radix UI ── the real shadcn foundation
   │      │
   │      ├── ui.watermelon.sh ── components distributed via shadcn CLI
   │      └── Kokonut UI ── components distributed via shadcn CLI
   │
   ├── anime.js ── standalone, framework-agnostic, no prerequisites
   │
   └── Realtimecolors.com / Haikei.app ── no install at all, browser tools only
```

**The single biggest decision**: do you set up a *real* shadcn foundation (`npx shadcn@latest init`) from project day one? If yes, Watermelon UI and Kokonut UI become simple copy-paste installs. If you build hand-rolled "shadcn-style" components instead (like ThreatHunter did), those two libraries won't drop in cleanly later — you'd be retrofitting the whole foundation, not just adding a component.

---

## 1. Motion (motion.dev, formerly Framer Motion)

- **What it is**: The most widely-used React animation library. Declarative animations via a `motion.div` component API, plus gesture support (drag, hover, tap), layout animations, and scroll-triggered effects.
- **Cost**: Free, MIT license.
- **Prerequisites**: None beyond React. Standalone.
- **How to connect/install**: `npm install motion`
- **Where it's used well**: Page transitions, modal/dialog entry-exit, list item stagger animations, drag-to-reorder, scroll-reveal effects, button micro-interactions.
- **Connects to**: Motion Primitives is built directly on top of this — install Motion first if you want Motion Primitives components.

## 2. Motion Primitives (motion-primitives.com)

- **What it is**: A collection of pre-built, animated UI components (text effects, image reveals, animated buttons, cursors) built using Motion.
- **Cost**: Free, MIT license.
- **Prerequisites**: Motion must be installed first (see #1). Components are typically copy-pasted via a CLI command shown on each component's page (often shadcn-CLI-style, but check per component — some are plain copy-paste).
- **How to connect/install**: Browse the site, pick a component, copy the install/CLI command it shows, run it. No account needed.
- **Where it's used well**: Hero sections, landing pages, marketing-heavy pages where visual flourish matters more than density. Less suited to data-dense dashboards/tools.

## 3. anime.js

- **What it is**: A lightweight, dependency-free JavaScript animation engine. Framework-agnostic — not React-specific, works with vanilla JS, Vue, or anything.
- **Cost**: Free, MIT license.
- **Prerequisites**: None. No shadcn, no Motion, no Tailwind even required.
- **How to connect/install**: `npm install animejs`
- **Where it's used well**: SVG path animations, complex timeline-based sequences, canvas-based effects, projects not using React (or wanting animation logic decoupled from component framework). Generally a lower-level tool than Motion — more control, more manual wiring.
- **Connects to**: Nothing else on this list requires it; it's an alternative to Motion, not a companion.

## 4. ui.watermelon.sh

- **What it is**: A component library/registry (buttons, cards, forms, etc.) built with React 19 + Tailwind v4 + Radix + Motion under the hood.
- **Cost**: Free.
- **Prerequisites**: Real shadcn CLI setup (`components.json` present), which brings in Radix UI as a dependency. Motion is also a dependency of some components.
- **How to connect/install**: `npx shadcn@latest init` first (if not already set up), then use the specific `npx shadcn add <watermelon-component-url>` command shown per component on their site.
- **Where it's used well**: Anywhere you'd use shadcn components — forms, dialogs, navigation, data display — but with more visual polish/animation baked in than vanilla shadcn.

## 5. Kokonut UI

- **What it is**: Another shadcn-CLI-distributed component collection, similar positioning to Watermelon UI — pre-styled, animated components on the shadcn foundation.
- **Cost**: Free (check current license per component; most shadcn-registry sites are MIT).
- **Prerequisites**: Same as Watermelon UI — real shadcn CLI setup + Radix.
- **How to connect/install**: Same pattern — `npx shadcn add <kokonut-component-url>` once shadcn is initialized.
- **Where it's used well**: Same use cases as Watermelon UI. Generally you'd pick one primary component source (not mix many) to keep visual language consistent — evaluate both and choose based on which components fit your specific project's aesthetic, don't install from both by default.

## 6. Realtimecolors.com

- **What it is**: An interactive, live-preview color palette tool — pick a base color and see the full palette (background, text, primary, secondary, accent) applied to a mock UI in real time, with contrast checking built in.
- **Cost**: Free, browser-based.
- **Prerequisites**: None. Not a package — nothing to install.
- **How to connect/use**: Visit the site directly in a browser, adjust colors interactively, export the resulting CSS variables or hex values, paste them into your Tailwind config / CSS variables file yourself.
- **Where it's used well**: Once, early in a project, to establish a cohesive color system before building components — not an ongoing dependency.

## 7. Haikei.app

- **What it is**: A generator for SVG background shapes — blobs, waves, gradient meshes, layered shapes — for hero sections and section dividers.
- **Cost**: Free, browser-based (some premium shapes may be paid — check at time of use).
- **Prerequisites**: None. Not a package.
- **How to connect/use**: Visit the site, generate and customize a shape, download the SVG, drop it into your project's `public/` or `assets/` folder, reference it as an image or inline SVG.
- **Where it's used well**: Marketing/landing pages wanting organic visual interest behind content. Rarely appropriate for dense, functional dashboards or tools (adds visual noise without informational value).

## 8. Manus.im

- **What it is**: An AI agent platform (autonomous task execution), not a frontend design/component resource at all.
- **Relevance**: Almost certainly not applicable to frontend design work — verify what's actually being referenced before assuming it belongs on this list for a given project.

## 9. bklit UI

- **What it is**: Unverified at time of writing — name should be confirmed (exists? typo of something else? a real but obscure library?) before evaluating for any project. Don't assume relevance or install based on the name alone.

---

## How to decide, per project

1. What is this project — dense/functional (dashboard, internal tool, admin panel) or expressive/marketing (landing page, portfolio, product site)? Motion-heavy libraries and organic backgrounds (Haikei) suit the second far more than the first.
2. Is a real shadcn foundation already set up, or hand-rolled components? This gates #4 and #5 entirely.
3. Is animation solving a real UX problem (loading feedback, state-change clarity, spatial continuity between pages) or purely decorative? Prioritize the former; treat the latter as optional polish, sequenced after core functionality works.
4. Fundamentals first, always: typography scale, WCAG-AA contrast, consistent spacing/composition. No library on this list substitutes for getting those right.
