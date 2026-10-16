import { createServerFn } from "@tanstack/react-start";

type Finding = { id: string; title: string; severity: string; evidence: string; recommendation: string };

function cfg() {
  const url = process.env["SURREALDB_URL"];
  const key = process.env["SURREALDB_API_KEY"];
  const ctx = process.env["SURREALDB_CONTEXT_ID"];
  if (!url || !key || !ctx) throw new Error("SurrealDB Agent Memory not configured");
  return {
    base: `${url.replace(/\/$/, "")}/api/v1/${ctx}`,
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
  };
}

// Flight recorder: one memory per finding so recall can match per-issue.
export const recordFlight = createServerFn({ method: "POST" })
  .inputValidator((d: { target: string; mode: "real" | "simulated"; findings: Finding[] }) => {
    if (!d || typeof d.target !== "string" || !Array.isArray(d.findings)) throw new Error("bad input");
    return { target: d.target.slice(0, 300), mode: d.mode, findings: d.findings.slice(0, 30) };
  })
  .handler(async ({ data }) => {
    const { base, headers } = cfg();
    const at = new Date().toISOString();
    const texts = data.findings.map(
      (f) =>
        `[Penetration Monkey flight ${at}] mode=${data.mode} target=${data.target} finding=${f.id} severity=${f.severity} title="${f.title}" evidence="${f.evidence.slice(0, 300)}" recommendation="${f.recommendation}"`,
    );
    if (texts.length === 0)
      texts.push(`[Penetration Monkey flight ${at}] mode=${data.mode} target=${data.target} — no findings.`);
    let saved = 0;
    for (const text of texts) {
      const r = await fetch(`${base}/facts`, { method: "POST", headers, body: JSON.stringify({ text, infer: "none" }) });
      if (r.ok) saved++;
    }
    return { saved, total: texts.length, at };
  });

export const recallFlights = createServerFn({ method: "POST" })
  .inputValidator((d: { query: string }) => ({ query: String(d?.query ?? "").slice(0, 500) || "Penetration Monkey flight recommendation" }))
  .handler(async ({ data }) => {
    const { base, headers } = cfg();
    const r = await fetch(`${base}/query`, { method: "POST", headers, body: JSON.stringify({ query: data.query, limit: 10 }) });
    if (!r.ok) throw new Error(`SurrealDB recall failed: ${r.status}`);
    const j = (await r.json()) as { hits?: { id: string; text: string; score: number; occurredAt?: string }[]; queryMs?: number };
    return {
      queryMs: j.queryMs ?? 0,
      hits: (j.hits ?? [])
        .filter((h) => h.text.includes("Penetration Monkey flight"))
        .map((h) => ({ id: h.id, text: h.text, score: h.score, at: h.occurredAt ?? null })),
    };
  });
