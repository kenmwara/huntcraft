// node worker/request/test.mjs : field rules only (validate() needs no Cloudflare runtime)
import assert from "node:assert";
const src = (await import("node:fs")).readFileSync(new URL("./src/index.js", import.meta.url), "utf8")
  .replace(/^import .*$/m, "const EmailMessage = class {};");
const { validate } = await import("data:text/javascript," + encodeURIComponent(src));

const ok = { name: "RDP-Flare", confirm: true, token: "t" };
assert.ok(validate(ok).fields);
assert.match(validate({ ...ok, name: " " }).error, /hunt name/);
assert.match(validate({ ...ok, confirm: false }).error, /Tick the box/);
assert.match(validate({ ...ok, answers: "x" }).error, /Unexpected field/);
assert.ok(validate({ ...ok, website: "spam" }).honeypot);
assert.match(validate({ ...ok, name: "x".repeat(121) }).error, /too long/);
assert.match(validate({ ...ok, questions: "x".repeat(8001) }).error, /too long/);
assert.match(validate({ ...ok, link: "javascript:alert(1)" }).error, /https/);
assert.ok(validate({ ...ok, link: "https://www.skool.com/x" }).fields);
assert.match(validate({ ...ok, contact: 5 }).error, /Couldn/);
assert.match(validate([]).error, /Couldn/);
console.log("validate: all checks pass");
