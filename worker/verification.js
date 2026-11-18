import { UpstreamError } from "./client.js";

const BROWSER_TYPES = new Set([
  "1", "2", "3", "5", "6", "7", "8", "10", "12", "13",
  "15", "16", "24", "34", "124", "134", "102", "103", "1024", "1034",
]);

const memoryFallback = new Map();

function isVerificationUrl(value) {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.origin === "https://img.client.10010.com"
      && url.pathname === "/loginRisk/index.html"
      && !url.username
      && !url.password;
  } catch {
    return false;
  }
}

function randomHex(bytes = 16) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function createOperatorVerification(kv, { ttlSeconds = 300 } = {}) {
  async function getEntry(id) {
    if (kv) {
      return await kv.get(`verify:${id}`, "json");
    }
    const entry = memoryFallback.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      memoryFallback.delete(id);
      return null;
    }
    return entry;
  }

  async function putEntry(id, entry) {
    if (kv) {
      await kv.put(`verify:${id}`, JSON.stringify(entry), { expirationTtl: ttlSeconds });
      return;
    }
    memoryFallback.set(id, { ...entry, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async function deleteEntry(id) {
    if (kv) {
      await kv.delete(`verify:${id}`);
      return;
    }
    memoryFallback.delete(id);
  }

  return {
    async request(action, client, createFields) {
      const { operatorVerificationId: id, operatorResultToken: token } = client;
      if (!id && !token) return { fields: createFields(), cookies: {} };

      const entry = id ? await getEntry(id) : null;
      if (
        !entry
        || entry.action !== action
        || entry.phone !== client.phone
        || entry.deviceId !== client.deviceId
        || typeof token !== "string"
        || !/^[\x21-\x7e]{1,4096}$/.test(token)
      ) {
        throw new UpstreamError("联通验证已失效或与当前登录不匹配，请重新开始");
      }

      await deleteEntry(id);
      return { fields: { ...entry.fields, resultToken: token }, cookies: entry.cookies || {} };
    },

    async challenge(json, action, client, { fields, cookies }) {
      if (!["ECS99998", "ECS99999"].includes(json?.code)) return null;
      const type = String(json.type || "");
      const requiresApp = type === "4";
      const browserSupported = BROWSER_TYPES.has(type)
        && isVerificationUrl(json.url)
        && typeof json.mobile === "string"
        && Boolean(json.mobile);

      const verification = { type, requiresApp, browserSupported };
      if (!browserSupported || requiresApp) return verification;

      const id = randomHex(16);
      await putEntry(id, {
        action,
        phone: client.phone,
        deviceId: client.deviceId,
        fields,
        cookies,
      });

      return { ...verification, id, url: json.url, context: json };
    },
  };
}
