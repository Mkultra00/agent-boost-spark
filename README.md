# Penetration Monkey

> Autonomous red-teaming for AI agents — sandboxed in Daytona, traced in Arize, remembered in SurrealDB.

**Built by:** Frank Yu (creator/lead) · Tom Kang (collaborator)

Penetration Monkey deploys a swarm of attacker agents against a target AI agent inside an isolated sandbox. Every prompt, tool call, and response is captured as a trace span, and every confirmed exploit is produced as a **trace-backed vulnerability report** that can be re-tested after a fix.

> **Status:** Hackathon prototype (Daytona HackSprint × Arize AI, NYC, October 2026). The current UI runs on simulated data; sponsor integrations are in progress.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Scripts](#scripts)
- [Roadmap](#roadmap)
- [Security](#security)
- [Team](#team)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Live attack trace** — streams attacker, target, judge, memory, and trace events in real time.
- **Holographic swarm view** — interactive 3D view of the orchestrator, attacker agents, tools, and color-coded traffic.
- **Judge-verified findings** — an LLM judge scores each exploit (`exploit_success`, `novelty`, `severity`).
- **Retest loop** — replays exploit chains against patched targets to confirm fixes hold.
- **Sandboxed by default** — each run executes in a disposable workspace with an egress allowlist.

## Architecture

```text
            ┌──────────────┐
            │  COMMANDER   │  orchestrator
            └──────┬───────┘
     ┌─────────────┼──────────────┐
  RECON        INJECTOR         EXFIL ...   attacker agents
     └─────────────┼──────────────┘
                   ▼
        ┌─────────────────────┐
        │  Daytona sandbox    │  target agent + tools
        └─────────┬───────────┘
          spans   │   findings / memory
                  ▼
        Arize (traces, evals)   SurrealDB (runs, findings, memory graph)
```

| Component | Responsibility |
| --- | --- |
| **Daytona** | Disposable, isolated workspace per run |
| **Arize** | OpenInference spans and LLM-as-judge evaluations |
| **SurrealDB** | Graph storage for runs, findings, and attacker memory |

## Tech Stack

- [TanStack Start](https://tanstack.com/start) (React 19, SSR) on Vite 7
- Tailwind CSS v4
- Three.js (holographic swarm view)
- TypeScript, Vitest, ESLint, Prettier

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) ≥ 1.1 (or Node.js ≥ 20)

### Install and run

```bash
git clone <your-repo-url> penetration-monkey
cd penetration-monkey
bun install
bun run dev
```

Then open http://localhost:8080 and press **Start run**.

## Project Structure

```text
public/
  swarm.html          # Prebuilt holographic swarm view
src/
  routes/
    __root.tsx        # Root layout and document head
    index.tsx         # Console: live trace, stats, swarm view
  lib/                # Shared utilities
  styles.css          # Tailwind theme and design tokens
  test/               # Vitest tests
```

## Scripts

| Command | Description |
| --- | --- |
| `bun run dev` | Start the development server |
| `bun run build` | Build for production |
| `bun run preview` | Preview the production build |
| `bunx vitest run` | Run the test suite |
| `bun run lint` | Lint the codebase |

## Roadmap

- [x] Console UI with simulated attack run
- [x] 3D holographic swarm visualization
- [ ] Daytona sandbox provisioning per run
- [ ] Arize OpenInference tracing and evals
- [ ] SurrealDB persistence for runs and findings
- [ ] Exportable vulnerability report (Markdown/PDF)

## Security

Penetration Monkey is meant **only** for systems you own or are explicitly authorized to test. Attacks must run inside the sandbox, with egress restricted to an allowlist. Report vulnerabilities in this project privately to the maintainers instead of opening a public issue.

## Team

- **Frank Yu** — creator and lead
- **Tom Kang** — collaborator

## Contributing

1. Fork the repo and create a branch: `git checkout -b feat/my-change`
2. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
3. Make sure `bunx vitest run` and `bun run lint` pass
4. Open a pull request

## License

MIT — see `LICENSE`.
