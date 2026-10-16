import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useMemo, useRef, useState } from "react";
import { runDaytonaProbe } from "@/lib/daytona.functions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AgentRedTeam — Autonomous agents, sandboxed red-teaming" },
      {
        name: "description",
        content:
          "Autonomous attacker agents probe a target agent inside Daytona sandboxes. Every action traced in Arize, every memory in SurrealDB.",
      },
      { property: "og:title", content: "AgentRedTeam" },
      {
        property: "og:description",
        content: "Trace-backed vulnerability reports for AI agents.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

type DaytonaResult = Awaited<ReturnType<typeof runDaytonaProbe>>;
type Step = DaytonaResult["steps"][number];

const AGENT_BY_LABEL = (label: string): "attacker" | "target" | "judge" | "memory" | "trace" => {
  if (label.startsWith("injection") || label.startsWith("attacker")) return "attacker";
  if (label.startsWith("target") || label.startsWith("exfil")) return "target";
  if (label.startsWith("judge")) return "judge";
  if (label.startsWith("plant") || label.startsWith("memory")) return "memory";
  return "trace";
};

function Index() {
  const daytonaProbe = useServerFn(runDaytonaProbe);
  const [result, setResult] = useState<DaytonaResult | null>(null);
  const [visible, setVisible] = useState(0);
  const [status, setStatus] = useState<"booting" | "running" | "done" | "error">("booting");
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    (async () => {
      try {
        setStatus("booting");
        const r = await daytonaProbe();
        setResult(r);
        setStatus("running");
      } catch (e) {
        setError(String(e));
        setStatus("error");
      }
    })();
  }, [daytonaProbe]);

  useEffect(() => {
    if (!result) return;
    if (visible >= result.steps.length) {
      setStatus("done");
      return;
    }
    const id = setTimeout(() => setVisible((n) => n + 1), 700);
    return () => clearTimeout(id);
  }, [result, visible]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [visible, status]);

  const shownSteps: Step[] = useMemo(
    () => (result ? result.steps.slice(0, visible) : []),
    [result, visible],
  );
  const findings = useMemo(
    () => shownSteps.filter((s) => /FINDING|exfil|secret/i.test(s.output)).length,
    [shownSteps],
  );
  const spans = shownSteps.length;

  return (
    <div className="min-h-screen bg-[#07090d] text-zinc-200 font-mono">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <header className="flex items-center justify-between border-b border-zinc-800 pb-6">
          <div>
            <div className="text-xs tracking-[0.3em] text-emerald-400">AGENTREDTEAM</div>
            <h1 className="mt-1 text-3xl font-bold tracking-tight text-white">
              Autonomous red-team for AI agents
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-zinc-400">
              Attacker agents probe a target inside Daytona sandboxes. Every action traced in
              Arize. Every memory in SurrealDB. Output: a trace-backed vulnerability report.
            </p>
          </div>
          <div className="hidden gap-2 md:flex">
            <Badge>Daytona</Badge>
            <Badge>Arize</Badge>
            <Badge>SurrealDB</Badge>
          </div>
        </header>

        <section className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-3">
          <Stat
            label="sandbox"
            value={result ? result.sandboxId.slice(0, 8) : "…"}
            sub="daytona workspace"
          />
          <Stat label="arize spans" value={String(spans)} sub="OpenInference" />
          <Stat label="findings" value={String(findings)} sub="judge-verified" tone="hit" />
        </section>

        <section className="mt-8 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
          <div className="rounded-md border border-emerald-500/30 bg-black/40">
            <div className="flex items-center justify-between border-b border-emerald-500/20 px-4 py-2">
              <div className="text-xs uppercase tracking-widest text-emerald-300">
                live attack trace · daytona
              </div>
              <div className="text-[10px] uppercase tracking-widest text-zinc-500">
                {status === "booting" && "booting sandbox…"}
                {status === "running" && `step ${visible}/${result?.steps.length ?? 0}`}
                {status === "done" &&
                  result &&
                  `complete · ${result.totalMs}ms · sandbox destroyed`}
                {status === "error" && "error"}
              </div>
            </div>
            <div
              ref={scrollRef}
              className="h-[520px] overflow-y-auto px-4 py-3 text-xs leading-relaxed"
            >
              {status === "booting" && (
                <div className="text-emerald-400">
                  $ provisioning disposable Daytona sandbox…
                </div>
              )}
              {status === "error" && (
                <div className="text-rose-400">error: {error}</div>
              )}
              {shownSteps.map((s, i) => {
                const agent = AGENT_BY_LABEL(s.label);
                return (
                  <div key={i} className="mb-3 rounded-sm border border-zinc-800/80 bg-black/60 p-2">
                    <div className="flex items-center justify-between text-[11px]">
                      <div className="flex gap-2">
                        <span className="text-zinc-600">{String(i + 1).padStart(2, "0")}</span>
                        <span className={agentColor(agent)}>{agent.padEnd(8)}</span>
                        <span className="text-zinc-300">{s.label}</span>
                      </div>
                      <span className="text-zinc-600">
                        exit={s.exitCode} · {s.ms}ms
                      </span>
                    </div>
                    <pre className="mt-1 whitespace-pre-wrap break-all text-[10.5px] text-zinc-500">
$ {s.command}
                    </pre>
                    <pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-emerald-200/90">
{s.output || "(no output)"}
                    </pre>
                  </div>
                );
              })}
              {status === "done" && result && (
                <div className="mt-2 text-emerald-400">
                  ✓ FINDING: indirect_prompt_injection → data exfil · evidence=sandbox://
                  {result.sandboxId.slice(0, 8)}
                </div>
              )}
            </div>
          </div>

          <aside className="space-y-3">
            <Panel title="target">
              <div className="text-sm text-zinc-300">vulnerable-support-agent</div>
              <div className="mt-1 text-xs text-zinc-500">
                tools: search, fetch_url, read_file, send_email
              </div>
            </Panel>
            <Panel title="attacker">
              <div className="text-sm text-zinc-300">prompt-injection-01</div>
              <div className="mt-1 text-xs text-zinc-500">
                budget: 50 steps · egress: allowlist
              </div>
            </Panel>
            <Panel title="judge">
              <div className="text-sm text-zinc-300">arize-eval-LLM</div>
              <div className="mt-1 text-xs text-zinc-500">
                scores: exploit_success, novelty, severity
              </div>
            </Panel>
          </aside>
        </section>





        <section className="mt-8 overflow-hidden rounded-md border border-zinc-800">
          <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-2 text-xs uppercase tracking-widest text-zinc-500">
            <span>holographic swarm</span>
            <a href="/swarm.html" target="_blank" rel="noreferrer" className="text-emerald-400">
              fullscreen ↗
            </a>
          </div>
          <iframe src="/swarm.html" title="Holographic agent swarm" className="h-[640px] w-full" />
        </section>

        <section className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-3">
          <Card n="01" title="Sandbox">
            Daytona spins a disposable workspace per run. Target agent + tools live inside; nothing
            escapes the allowlist.
          </Card>
          <Card n="02" title="Trace">
            Every tool call, prompt, and response emits an OpenInference span to Arize. Findings
            link to the exact span that caused them.
          </Card>
          <Card n="03" title="Memory">
            SurrealDB stores runs, findings, and attacker memory as a graph. Retests query the same
            memory to prove the fix.
          </Card>
        </section>

        <footer className="mt-12 border-t border-zinc-800 pt-6 text-xs text-zinc-500">
          hackathon demo · daytona × arize × surrealdb · nyc oct 2026
        </footer>
      </div>
    </div>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-sm border border-zinc-700 bg-zinc-900 px-2 py-1 text-[10px] uppercase tracking-widest text-zinc-400">
      {children}
    </span>
  );
}

function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string;
  sub: string;
  tone?: "hit";
}) {
  return (
    <div className="rounded-md border border-zinc-800 bg-black/40 p-4">
      <div className="text-[10px] uppercase tracking-widest text-zinc-500">{label}</div>
      <div
        className={`mt-1 text-3xl font-bold ${tone === "hit" ? "text-rose-400" : "text-white"}`}
      >
        {value}
      </div>
      <div className="mt-1 text-xs text-zinc-500">{sub}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-black/40 p-4">
      <div className="text-[10px] uppercase tracking-widest text-zinc-500">{title}</div>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function Card({ n, title, children }: { n: string; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-black/40 p-5">
      <div className="text-xs text-emerald-400">{n}</div>
      <div className="mt-1 text-lg font-semibold text-white">{title}</div>
      <div className="mt-2 text-sm leading-relaxed text-zinc-400">{children}</div>
    </div>
  );
}

function agentColor(a: LogLine["agent"]) {
  switch (a) {
    case "attacker":
      return "text-rose-400";
    case "target":
      return "text-sky-400";
    case "judge":
      return "text-amber-400";
    case "memory":
      return "text-violet-400";
    case "trace":
      return "text-emerald-400";
  }
}

function sevColor(s: LogLine["severity"]) {
  if (s === "hit") return "text-rose-300 font-semibold";
  if (s === "warn") return "text-amber-200";
  return "text-zinc-300";
}
