# Penetration Monkey

> An agentic web-security scanner. It drives a real cloud browser against a target site, runs
> probes in disposable sandboxes, traces every step, and remembers findings so a re-scan shows
> what changed.

Built at the **Daytona HackSprint w/ Arize AI, NYC, October 2026.** Team: Om Thakur, Frank Yu.

---

## What it does

1. You give it a URL.
2. A real **Anchor** cloud browser renders the page, and the scanner runs deterministic security
   checks on it (HTTPS, HSTS, Content-Security-Policy, clickjacking defense, cookie flags, insecure
   forms), each scored pass / warn / fail with an OWASP reference.
3. A disposable **Daytona** sandbox runs an active probe that acts out an indirect-prompt-injection
   scenario against a planted secret, inside an egress allowlist, then is destroyed.
4. Every step is emitted as an OpenInference span to **Arize** as a trace-backed evidence record.
5. Each finding is written to **SurrealDB Agent Memory**, so a later scan of the same site
   supersedes the old result and the briefing can show the history ("CSP was missing, now present").
6. An **ElevenLabs** voice reads the executive briefing aloud.

The methodology (contained attacker, canary-based success, evidence mapped to OWASP ASI, MITRE
ATLAS and EU AI Act Art. 15) follows Frank Yu's agent-pentest paper.

---

## Tech stack

### Application
| Layer | Choice | Version |
|---|---|---|
| Framework | TanStack Start (full-stack React) | react-start 1.168 |
| UI library | React | 19.2 |
| Routing | TanStack Router | 1.170 |
| Build tool | Vite | 8.1 |
| Styling | Tailwind CSS | 4.2 |
| Components | shadcn/ui (Radix primitives) | current |
| 3D view | Three.js r128 (holographic swarm, `public/swarm.html`) | r128 |
| Language | TypeScript | 5.x |
| Package manager | Bun | bun.lock |
| Hosting | Lovable (Cloudflare-Worker-style server runtime) | n/a |

### Server layer
Backend logic runs as **TanStack server functions** (`createServerFn`), so every sponsor API key
stays server-side and never reaches the browser. There is no separate backend service; the server
functions execute in Lovable's hosting runtime. Sponsor APIs are called directly over HTTPS with
`fetch`, with no heavy SDKs, to keep the bundle small.

### Sponsor integrations
| Sponsor | What it does here | How it is called | File | Status |
|---|---|---|---|---|
| **Anchor Browser** | Renders the target URL through a real cloud browser session that the scan reads | REST: `POST /v1/sessions`, `POST /v1/tools/fetch-webpage`, `DELETE /v1/sessions/{id}`; header `anchor-api-key` | `src/lib/compliance.functions.ts` | Live (needs `ANCHOR_API_KEY`) |
| **Daytona** | Creates a disposable sandbox, runs the probe, destroys it | REST: `app.daytona.io/api` + toolbox proxy; `Bearer` auth | `src/lib/daytona.functions.ts` | Live (needs `DAYTONA_API_KEY`) |
| **Arize AI** | Receives real OpenInference spans (the evidence trail) over OTLP | `POST otlp.arize.com/v1/traces`; headers `space_id`, `api_key`, Bearer | `src/lib/arize.server.ts` | Live (needs `ARIZE_API_KEY`, `ARIZE_SPACE_ID`) |
| **SurrealDB Agent Memory** | Stores each finding; a re-scan supersedes the old fact (time-aware memory) | REST: `POST /api/v1/{context}/facts` and `/query`; `Bearer sp-…` | `src/lib/surreal.server.ts` | In progress (needs `SURREAL_*`) |
| **ElevenLabs** | Reads the executive briefing aloud | REST: `POST /v1/text-to-speech/{voiceId}`; header `xi-api-key` | `src/lib/voice.functions.ts` | Live (needs `ELEVENLABS_API_KEY`) |
| AWS | Not used in this build | n/a | n/a | Out of scope |

---

## Environment variables

Set these in the hosting project's environment (Lovable project settings). Never commit them.

```
ANCHOR_API_KEY=
DAYTONA_API_KEY=
ARIZE_API_KEY=
ARIZE_SPACE_ID=
ELEVENLABS_API_KEY=
SURREAL_URL=https://srv1.spectron.aws-usw2.surreal.cloud
SURREAL_CONTEXT_ID=06gkbs4v9lp875tegd7mcs6hlg
SURREAL_API_KEY=
```

Each integration degrades gracefully: if its key is missing, that panel reports "not connected"
instead of failing the whole run. The UI labels live results versus demo replay.

---

## Getting started

```sh
bun install
bun run dev
```

Open the local URL Vite prints. Without keys, the scanner still renders and the swarm view plays a
labelled demo replay; with keys set, panels call the real sponsor APIs.

---

## Project structure

```text
src/
  routes/index.tsx            landing, console tab, briefer tab, swarm link
  lib/
    compliance.functions.ts   Anchor render + deterministic security checks
    daytona.functions.ts      sandbox create / exec / destroy, feeds Arize
    arize.server.ts           OpenInference spans over OTLP
    voice.functions.ts        ElevenLabs text to speech
    surreal.server.ts         Agent Memory store + query (in progress)
public/
  swarm.html                  Three.js holographic swarm (simulate / replay / live)
```

---

## Honesty note (what is real vs modeled)

- **Real:** the Anchor browser render, the security checks, the Daytona sandbox lifecycle, the Arize
  spans, the ElevenLabs audio.
- **Modeled:** the Daytona probe currently acts out the injection with shell commands rather than a
  live LLM agent; the swarm view runs a simulation until wired to live events. Both are labelled as
  such in the UI and are the first items on the roadmap.
- All target data is synthetic. No real patient or customer data is used.

---

## Team

- **Om Thakur** (NYU Computer Engineering) — integrations, scanner, build.
- **Frank Yu** — agent-pentest methodology (threat model, canary success criteria, control mapping).
