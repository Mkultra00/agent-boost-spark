// Send OpenInference-style spans to Arize via OTLP/HTTP JSON.
// Docs: https://docs.arize.com/arize/large-language-models/tracing/how-to-tracing-manual

const OTLP = "https://otlp.arize.com/v1/traces";

function hex(bytes: number) {
  let s = "";
  for (let i = 0; i < bytes; i++) s += Math.floor(Math.random() * 256).toString(16).padStart(2, "0");
  return s;
}

type Attr = { key: string; value: { stringValue?: string; intValue?: string; boolValue?: boolean } };
const sAttr = (key: string, v: string): Attr => ({ key, value: { stringValue: v } });
const iAttr = (key: string, v: number): Attr => ({ key, value: { intValue: String(v) } });

export type FlightStep = {
  label: string;
  agent: string;
  command: string;
  output: string;
  exitCode: number;
  ms: number;
};

export async function sendFlightToArize(opts: {
  runName: string;
  sandboxId: string;
  steps: FlightStep[];
  totalMs: number;
}): Promise<{ sent: boolean; traceId: string; spanCount: number; error?: string; projectName: string }> {
  const apiKey = process.env["ARIZE_API_KEY"];
  const spaceId = process.env["ARIZE_SPACE_ID"];
  const projectName = "penetrationmonkey";
  const traceId = hex(16);
  if (!apiKey || !spaceId) {
    return { sent: false, traceId, spanCount: 0, projectName, error: "ARIZE_API_KEY or ARIZE_SPACE_ID missing" };
  }

  const nowNs = BigInt(Date.now()) * 1_000_000n;
  const totalNs = BigInt(opts.totalMs) * 1_000_000n;
  const rootStart = nowNs - totalNs;
  const rootSpanId = hex(8);

  const spans: unknown[] = [
    {
      traceId,
      spanId: rootSpanId,
      name: opts.runName,
      kind: 1,
      startTimeUnixNano: String(rootStart),
      endTimeUnixNano: String(nowNs),
      attributes: [
        sAttr("openinference.span.kind", "AGENT"),
        sAttr("agent.name", "orchestrator"),
        sAttr("sandbox.id", opts.sandboxId),
        iAttr("steps.count", opts.steps.length),
      ],
      status: { code: 1 },
    },
  ];

  let cursor = rootStart;
  for (const s of opts.steps) {
    const stepNs = BigInt(Math.max(s.ms, 1)) * 1_000_000n;
    const start = cursor;
    const end = cursor + stepNs;
    cursor = end;
    const kind = s.label.startsWith("judge") ? "CHAIN" : s.label.includes("exec") || s.command ? "TOOL" : "AGENT";
    spans.push({
      traceId,
      spanId: hex(8),
      parentSpanId: rootSpanId,
      name: `${s.agent}:${s.label}`,
      kind: 1,
      startTimeUnixNano: String(start),
      endTimeUnixNano: String(end),
      attributes: [
        sAttr("openinference.span.kind", kind),
        sAttr("agent.name", s.agent),
        sAttr("tool.name", "daytona.exec"),
        sAttr("input.value", s.command),
        sAttr("output.value", s.output.slice(0, 1500)),
        iAttr("exit.code", s.exitCode),
        iAttr("duration.ms", s.ms),
      ],
      status: { code: s.exitCode === 0 ? 1 : 2 },
    });
  }

  const payload = {
    resourceSpans: [
      {
        resource: {
          attributes: [
            sAttr("model_id", projectName),
            sAttr("model_version", "v1"),
            sAttr("openinference.project.name", projectName),
          ],
        },
        scopeSpans: [
          {
            scope: { name: "penetrationmonkey.flight" },
            spans,
          },
        ],
      },
    ],
  };

  try {
    const r = await fetch(OTLP, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        space_id: spaceId,
        api_key: apiKey,
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const t = await r.text();
      return { sent: false, traceId, spanCount: spans.length, projectName, error: `${r.status} ${t.slice(0, 200)}` };
    }
    return { sent: true, traceId, spanCount: spans.length, projectName };
  } catch (e) {
    return { sent: false, traceId, spanCount: spans.length, projectName, error: String(e).slice(0, 200) };
  }
}
