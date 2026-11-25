// HuntCraft "Request a hunt" backend: POST /api/request on huntcraft.kenmwara.com.
// A Worker, not a Pages Function: Pages has no send_email binding. Secrets (Pages-free, set with wrangler):
//   TURNSTILE_SECRET  Turnstile widget secret        NOTIFY_TO  where the notification goes (a verified address)
// Bindings: DB (D1 hunt_requests), RL (KV rate limit), EMAIL (send_email). The IP is never stored: the rate-limit key
// is a hash of it and expires after an hour.

const LIMITS = { name: 120, link: 500, workspace: 120, questions: 8000, contact: 200 };
const ALLOWED = new Set([...Object.keys(LIMITS), "confirm", "website", "token"]); // website = honeypot, token = Turnstile
const PER_HOUR = 5;
const FROM = "huntcraft@kenmwara.com";
const TRY_AGAIN = "Couldn't send. Try again in a minute.";

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const reject = (msg, status = 400) => json({ ok: false, error: msg }, status);

async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// Field rules only; no I/O. Returns { fields } or { error }.
export function validate(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: TRY_AGAIN };
  for (const k of Object.keys(body)) if (!ALLOWED.has(k)) return { error: "Unexpected field in the form. Refresh the page and try again." };
  if (body.website) return { error: "That didn't look like a person sending it. Refresh the page and try again.", honeypot: true };
  const fields = {};
  for (const [k, max] of Object.entries(LIMITS)) {
    const v = body[k] == null ? "" : body[k];
    if (typeof v !== "string") return { error: TRY_AGAIN };
    const t = v.trim();
    if (t.length > max) return { error: `That ${k === "questions" ? "list of questions" : k} is too long (${max} characters at most).` };
    fields[k] = t;
  }
  if (!fields.name) return { error: "Add the hunt name." };
  if (fields.link && !/^https?:\/\/\S+$/i.test(fields.link)) return { error: "The link should start with https://" };
  if (body.confirm !== true) return { error: "Tick the box to confirm this is a practice or finished hunt." };
  return { fields };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== "/api/request") return reject("Not found", 404);
    if (req.method !== "POST") return reject("Use the form on /request", 405);
    const origin = req.headers.get("Origin");
    if (origin && origin !== url.origin) return reject(TRY_AGAIN, 403);
    if ((+req.headers.get("content-length") || 0) > 20000) return reject("That request is too long.", 413);

    let body;
    try { body = await req.json(); } catch { return reject(TRY_AGAIN); }
    const v = validate(body);
    if (v.error) return reject(v.error);
    const f = v.fields;

    // rate limit: 5 accepted requests per hour per (hashed) IP
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const rlKey = "rl:" + (await sha256("huntcraft|" + ip));
    const seen = JSON.parse((await env.RL.get(rlKey)) || "null") || { n: 0, until: Date.now() + 3600e3 };
    if (seen.n >= PER_HOUR) return reject("That's a lot of requests in one hour. Try again later.", 429);

    // Turnstile (required: without a secret nothing is accepted)
    if (!env.TURNSTILE_SECRET || typeof body.token !== "string" || !body.token) return reject(TRY_AGAIN, 400);
    const form = new FormData();
    form.append("secret", env.TURNSTILE_SECRET);
    form.append("response", body.token);
    form.append("remoteip", ip);
    const ts = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form })
      .then((r) => r.json()).catch(() => ({ success: false }));
    if (!ts.success) return reject("The spam check didn't pass. Refresh the page and try again.");

    const id = crypto.randomUUID(), created = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO hunt_requests (id, created_at, name, link, workspace, questions, contact, status) VALUES (?1,?2,?3,?4,?5,?6,?7,'new')"
    ).bind(id, created, f.name, f.link, f.workspace, f.questions, f.contact).run();
    seen.n += 1;
    await env.RL.put(rlKey, JSON.stringify(seen), { expiration: Math.floor(seen.until / 1000) });

    // notify Ken; the row is already safe, so a mail failure is logged, not shown
    if (env.NOTIFY_TO) {
      const text = [`Hunt: ${f.name}`, `Link: ${f.link || "-"}`, `Workspace: ${f.workspace || "-"}`, `Contact: ${f.contact || "-"}`,
        `Request id: ${id} (${created})`, "", "Questions:", f.questions || "-", "",
        "Review: python tools/review.py, Requests tab."].join("\n");
      try {
        await env.EMAIL.send({ from: { email: FROM, name: "HuntCraft" }, to: env.NOTIFY_TO.trim(),   // trim drops a stray BOM/newline from secret put
          subject: `HuntCraft request: ${f.name}`.replace(/[\r\n]+/g, " "), text });
      } catch (e) { console.log(`notify failed: ${e.code || ""} ${e.message}`); }
    }
    return json({ ok: true });
  },
};
