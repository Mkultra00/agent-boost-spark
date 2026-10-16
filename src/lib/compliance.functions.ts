import { createServerFn } from "@tanstack/react-start";

export type ComplianceCheck = {
  id: string;
  label: string;
  severity: "pass" | "warn" | "fail" | "info";
  detail: string;
};

export type ComplianceResult = {
  url: string;
  finalUrl: string;
  status: number;
  ms: number;
  via: "anchor" | "direct";
  headers: Record<string, string>;
  checks: ComplianceCheck[];
  htmlSnippet: string;
};

async function anchorRender(url: string, key: string): Promise<string | null> {
  // Real browser render via Anchor; returns rendered HTML or null.
  let id: string | undefined;
  try {
    const s = await fetch("https://api.anchorbrowser.io/v1/sessions", {
      method: "POST",
      headers: { "anchor-api-key": key, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!s.ok) return null;
    id = ((await s.json()) as { data?: { id?: string } }).data?.id;
    if (!id) return null;
    const r = await fetch(`https://api.anchorbrowser.io/v1/tools/fetch-webpage?sessionId=${id}`, {
      method: "POST",
      headers: { "anchor-api-key": key, "Content-Type": "application/json" },
      body: JSON.stringify({ url, format: "html" }),
    });
    return r.ok ? await r.text() : null;
  } catch {
    return null;
  } finally {
    if (id)
      await fetch(`https://api.anchorbrowser.io/v1/sessions/${id}`, {
        method: "DELETE",
        headers: { "anchor-api-key": key },
      }).catch(() => {});
  }
}

export const scanCompliance = createServerFn({ method: "POST" })
  .inputValidator((d: { url: string }) => {
    const u = new URL(d.url);
    if (!/^https?:$/.test(u.protocol)) throw new Error("http/https only");
    return { url: u.toString() };
  })
  .handler(async ({ data }): Promise<ComplianceResult> => {
    const t0 = Date.now();
    const anchorKey = process.env["ANCHOR_API_KEY"];

    const response = await fetch(data.url, {
      redirect: "follow",
      headers: { "User-Agent": "PenetrationMonkey-Compliance/1.0" },
    });
    const headers: Record<string, string> = {};
    response.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    const directBody = await response.text();
    const finalUrl = response.url || data.url;

    let via: "anchor" | "direct" = "direct";
    let body = directBody;
    if (anchorKey) {
      const rendered = await anchorRender(finalUrl, anchorKey);
      if (rendered) {
        body = rendered;
        via = "anchor";
      }
    }
    const u = new URL(finalUrl);

    const checks: ComplianceCheck[] = [];
    const push = (c: ComplianceCheck) => checks.push(c);

    push({
      id: "tls",
      label: "Transport (HTTPS)",
      severity: u.protocol === "https:" ? "pass" : "fail",
      detail:
        u.protocol === "https:"
          ? "Served over HTTPS."
          : "Site served over plaintext HTTP — PCI/GDPR/OWASP A02 violation.",
    });

    const hsts = headers["strict-transport-security"];
    push({
      id: "hsts",
      label: "HSTS",
      severity: hsts ? "pass" : "warn",
      detail: hsts ? hsts : "Missing Strict-Transport-Security header.",
    });

    const csp = headers["content-security-policy"];
    push({
      id: "csp",
      label: "Content-Security-Policy",
      severity: csp ? "pass" : "warn",
      detail: csp
        ? csp.length > 120
          ? csp.slice(0, 120) + "…"
          : csp
        : "No CSP header — XSS mitigations missing (OWASP A03).",
    });

    const xfo = headers["x-frame-options"];
    const frameAncestors = csp?.includes("frame-ancestors");
    push({
      id: "clickjacking",
      label: "Clickjacking defense",
      severity: xfo || frameAncestors ? "pass" : "warn",
      detail: xfo
        ? `X-Frame-Options: ${xfo}`
        : frameAncestors
          ? "CSP frame-ancestors set."
          : "No X-Frame-Options or CSP frame-ancestors.",
    });

    const refpol = headers["referrer-policy"];
    push({
      id: "referrer",
      label: "Referrer-Policy",
      severity: refpol ? "pass" : "info",
      detail: refpol || "Not set — browser default may leak URLs cross-origin.",
    });

    const perm = headers["permissions-policy"];
    push({
      id: "permissions",
      label: "Permissions-Policy",
      severity: perm ? "pass" : "info",
      detail: perm || "No Permissions-Policy — all browser features allowed.",
    });

    const xcto = headers["x-content-type-options"];
    push({
      id: "nosniff",
      label: "X-Content-Type-Options",
      severity: xcto === "nosniff" ? "pass" : "warn",
      detail: xcto || "Missing nosniff — MIME-sniffing risks.",
    });

    const setCookie = response.headers.get("set-cookie") || "";
    if (setCookie) {
      const insecure =
        !/secure/i.test(setCookie) ||
        !/httponly/i.test(setCookie) ||
        !/samesite/i.test(setCookie);
      push({
        id: "cookies",
        label: "Cookie flags",
        severity: insecure ? "fail" : "pass",
        detail: insecure
          ? "Cookie(s) missing Secure/HttpOnly/SameSite — session hijack risk."
          : "All cookies Secure+HttpOnly+SameSite.",
      });
    } else {
      push({
        id: "cookies",
        label: "Cookie flags",
        severity: "info",
        detail: "No Set-Cookie on this response.",
      });
    }

    const server = headers["server"] || headers["x-powered-by"];
    push({
      id: "fingerprint",
      label: "Server fingerprint",
      severity: server ? "warn" : "pass",
      detail: server
        ? `Discloses stack: ${server}`
        : "No Server/X-Powered-By leakage.",
    });

    const hasPrivacy = /privacy/i.test(body);
    const hasCookieBanner = /cookie|consent|gdpr/i.test(body);
    push({
      id: "privacy",
      label: "Privacy / GDPR notices",
      severity: hasPrivacy ? "pass" : "warn",
      detail: hasPrivacy
        ? `Privacy mentioned${hasCookieBanner ? " · cookie/consent language detected" : ""}.`
        : "No privacy policy link found on landing HTML.",
    });

    const forms = (body.match(/<form[\s\S]*?<\/form>/gi) || []).length;
    const insecureForm = /<form[^>]+action=["']http:\/\//i.test(body);
    push({
      id: "forms",
      label: "Forms",
      severity: insecureForm ? "fail" : forms ? "info" : "info",
      detail: insecureForm
        ? "Form posts over plaintext HTTP."
        : forms
          ? `${forms} form(s) detected.`
          : "No forms on landing page.",
    });

    return {
      url: data.url,
      finalUrl,
      status: response.status,
      ms: Date.now() - t0,
      via,
      headers,
      checks,
      htmlSnippet: body.slice(0, 400),
    };
  });
