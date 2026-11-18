import { parseCookieHeader } from "../server/src/upstream/cookies.js";
import { UpstreamError } from "./client.js";
import { createUnicomUpstream } from "./unicom.js";

const PHONE_PATTERN = /^1\d{10}$/;
const CODE_PATTERN = /^\d{4,8}$/;
const MIN_TOKEN_LENGTH = 20;
const MAX_BODY_BYTES = 16 * 1024;

const PROXY_QUERIES = new Map([
  ["/ocs_proxy", "queryOcs"],
  ["/basicdata_proxy", "queryBasicData"],
  ["/qci_proxy", "queryQci"],
]);

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function constantTimeEqual(a, b) {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

function readConfig(env) {
  const str = (k, fallback) => {
    const v = env[k];
    return typeof v === "string" && v.trim() ? v.trim() : fallback;
  };
  const timeout = Number(str("UNICOM_TIMEOUT_MS", "15000"));
  return {
    accessToken: str("ACCESS_TOKEN", ""),
    allowedOrigins: str("ALLOWED_ORIGINS", "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    upstream: {
      baseUrl: str("UNICOM_BASE_URL", "https://m.client.10010.com"),
      loginBaseUrl: str("UNICOM_LOGIN_BASE_URL", "https://loginxhm.10010.com"),
      appVersion: str("UNICOM_APP_VERSION", "android@13.0000"),
      appId: str("UNICOM_APP_ID", "ChinaunicomMobileBusiness"),
      deviceBrand: str("UNICOM_DEVICE_BRAND", "samsung"),
      deviceModel: str("UNICOM_DEVICE_MODEL", "SM-G9910"),
      androidVersion: str("UNICOM_ANDROID_VERSION", "12"),
      timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 15000,
      debugRaw: str("DEBUG_RAW", "false").toLowerCase() === "true",
      sendSmsPath: str("UNICOM_SEND_SMS_PATH", "/mobileService/sendRadomNum.htm"),
      loginPath: str("UNICOM_LOGIN_PATH", "/mobileService/radomLogin.htm"),
      passwordLoginPath: str("UNICOM_PASSWORD_LOGIN_PATH", "/mobileService/login.htm"),
      ocsPath: str("UNICOM_OCS_PATH", "/servicequerybusiness/operationservice/queryOcsPackageFlowLeftContentRevisedInJune"),
      basicDataPath: str("UNICOM_BASIC_DATA_PATH", "/servicebusiness/query/fiveg/getbasicdata"),
      qciPath: str("UNICOM_QCI_PATH", "/servicebusiness/newOrdered/queryOrderRelationship"),
    },
  };
}

async function parseJsonBody(request) {
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
    throw Object.assign(new Error("请求正文过大"), { statusCode: 413 });
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw Object.assign(new Error("请求正文必须是 JSON 对象"), { statusCode: 400 });
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw Object.assign(new Error("请求正文必须是 JSON 对象"), { statusCode: 400 });
  }
  return value;
}

function field(body, name) {
  const value = body?.[name];
  return typeof value === "string" ? value.trim() : "";
}

function operatorFields(body) {
  return {
    operatorVerificationId: field(body, "operatorVerificationId"),
    operatorResultToken: field(body, "operatorResultToken"),
  };
}

async function handleGetToken(action, body, upstream) {
  const failure = (msg) => jsonResponse({ status: "error", msg });
  const verificationReply = (result) =>
    jsonResponse({ status: "need_verification", msg: result.message, verification: result.verification });

  if (action === "send") {
    const phone = field(body, "phone");
    const deviceId = field(body, "deviceId");
    if (!PHONE_PATTERN.test(phone)) return failure("请输入有效的手机号");

    const result = await upstream.sendSmsCode({ phone, deviceId, ...operatorFields(body) });
    if (result.verification) return verificationReply(result);
    return jsonResponse({ status: result.ok ? "success" : "error", msg: result.message });
  }

  if (action === "login" || action === "password") {
    const isPassword = action === "password";
    const phone = field(body, "phone");
    const deviceId = field(body, "deviceId");
    const secret = isPassword
      ? (typeof body?.password === "string" ? body.password : "")
      : field(body, "code");

    if (!PHONE_PATTERN.test(phone)) return failure("请输入有效的手机号");
    if (isPassword && (secret.length < 8 || secret.length > 20)) {
      return failure("请输入 8–20 位联通 App 登录密码");
    }
    if (!isPassword && !CODE_PATTERN.test(secret)) {
      return failure("请输入有效的短信验证码");
    }

    const session = await upstream[isPassword ? "passwordLogin" : "smsLogin"]({
      phone,
      deviceId,
      ...operatorFields(body),
      ...(isPassword ? { password: secret } : { code: secret }),
    });
    if (session.verification) return verificationReply(session);
    return jsonResponse({
      status: "success",
      ecs_token: session.ecsToken,
      onlin_token: session.onlinToken,
      ...(session.cookie ? { cookie: session.cookie } : {}),
    });
  }

  return failure("未知的 action");
}

async function handleProxy(method, body, upstream) {
  const token = field(body, "ecs_token");
  if (token.length <= MIN_TOKEN_LENGTH) {
    return jsonResponse({ ok: false, code: "TOKEN_EXPIRED", raw: "missing" });
  }
  if (token.length > 4096 || /[^\x21-\x7e]|[;",\\]/.test(token)) {
    return jsonResponse({ ok: false, code: "BAD_REQUEST", msg: "Token 格式错误" }, 400);
  }
  const cookies = parseCookieHeader(body?.cookie);
  if (!cookies) {
    return jsonResponse({ ok: false, code: "BAD_REQUEST", msg: "登录会话格式错误" }, 400);
  }

  return jsonResponse(await upstream[method](token, cookies));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    if (pathname === "/healthz" && request.method === "GET") {
      return jsonResponse({ ok: true });
    }

    const isApiRoute = pathname === "/gettoken" || PROXY_QUERIES.has(pathname);
    if (!isApiRoute) {
      return env.ASSETS.fetch(request);
    }

    const config = readConfig(env);
    const origin = request.headers.get("origin");
    if (origin && origin !== url.origin && !config.allowedOrigins.includes(origin)) {
      return jsonResponse({ ok: false, status: "error", code: "ORIGIN_DENIED", msg: "不允许此来源访问后端" }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin || url.origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method !== "POST") {
      return jsonResponse({ ok: false, status: "error", code: "BAD_REQUEST", msg: "仅支持 POST 请求" }, 405);
    }

    let body;
    try {
      body = await parseJsonBody(request);
    } catch (error) {
      const status = error.statusCode || 400;
      return jsonResponse({ ok: false, status: "error", code: "BAD_REQUEST", msg: error.message }, status);
    }

    if (config.accessToken) {
      const actual = typeof body.access_token === "string" ? body.access_token : "";
      if (!constantTimeEqual(actual, config.accessToken)) {
        return jsonResponse({ ok: false, status: "error", code: "ACCESS_DENIED", msg: "后端访问密钥无效，请检查配置" }, 401);
      }
    }

    const upstream = createUnicomUpstream(config.upstream, env.VERIFICATION_KV);

    try {
      if (pathname === "/gettoken") {
        const action = url.searchParams.get("action")?.trim() || "";
        return await handleGetToken(action, body, upstream);
      }
      return await handleProxy(PROXY_QUERIES.get(pathname), body, upstream);
    } catch (error) {
      if (error instanceof UpstreamError) {
        if (pathname === "/gettoken") {
          return jsonResponse({ status: "error", msg: error.message });
        }
        return jsonResponse({ ok: false, msg: error.message, code: "UPSTREAM_ERROR" }, 502);
      }
      return jsonResponse({ ok: false, status: "error", code: "INTERNAL_ERROR", msg: "服务内部错误" }, 500);
    }
  },
};
