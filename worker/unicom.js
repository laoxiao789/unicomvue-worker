import {
  classifyUpstreamFailure,
  normalizeBasicData,
  normalizeOcs,
  normalizeQci,
} from "../server/src/upstream/normalize.js";
import { cookieHeader, mergeResponseCookies } from "../server/src/upstream/cookies.js";
import { postForm, UpstreamError } from "./client.js";
import { encryptCredential } from "./rsa.js";
import { createOperatorVerification } from "./verification.js";

function readTokenFromCookies(headers, name) {
  const raw = headers?.getSetCookie?.() ?? [];
  for (const cookie of raw) {
    const pair = cookie.split(";", 1)[0].trim();
    if (!pair.startsWith(`${name}=`)) continue;
    const value = pair.slice(name.length + 1);
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return "";
}

function upstreamMessage(json, fallback) {
  const message = json?.rsp_desc || json?.dsc || json?.desc || json?.msg || json?.message;
  return typeof message === "string" && message.trim() ? message.trim() : fallback;
}

function isSuccessCode(code) {
  return ["0", "0000", "00", "success"].includes(String(code ?? "").trim());
}

function randomSixDigits() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return String(buf[0] % 1_000_000).padStart(6, "0");
}

export function createUnicomUpstream(config, kv) {
  const loginConfig = { ...config, baseUrl: config.loginBaseUrl };
  const verification = createOperatorVerification(kv);

  const deviceFields = (deviceId) => ({
    appId: config.appId,
    version: config.appVersion,
    deviceId,
    deviceCode: deviceId,
    androidId: deviceId?.slice(8, 24),
    deviceBrand: config.deviceBrand,
    deviceModel: config.deviceModel,
    deviceOS: `android${config.androidVersion}`,
    keyVersion: "",
    isFirstInstall: "1",
  });

  function withRaw(result, json, text) {
    return config.debugRaw ? { ...result, _raw: json ?? text.slice(0, 4000) } : result;
  }

  async function query(path, token, normalize, cookies = {}) {
    const response = await postForm(config, path, {}, {
      cookies: Object.keys(cookies).length ? cookies : { ecs_token: token },
    });
    const { status, text, json } = response;

    const failure = classifyUpstreamFailure(text, json);
    if (failure) return withRaw(failure, json, text);

    const code = json.code ?? json.retCode;
    if (code !== undefined && !isSuccessCode(code)) {
      throw new UpstreamError(upstreamMessage(json, "查询失败"), { status, raw: text.slice(0, 200) });
    }

    return withRaw(normalize(json), json, text);
  }

  async function login(action, client) {
    const { phone, deviceId } = client;
    const isPassword = action === "password";
    const request = await verification.request(action, client, () => {
      const suffix = randomSixDigits();
      return {
        ...deviceFields(deviceId),
        mobile: encryptCredential(phone + suffix),
        password: encryptCredential((isPassword ? client.password : client.code) + suffix),
        ...(isPassword ? { simCount: "1" } : { loginStyle: "0" }),
        provinceChanel: "general",
        timestamp: new Date(Date.now() + 8 * 60 * 60_000).toISOString().replace(/\D/g, "").slice(0, 14),
      };
    });

    const response = await postForm(
      loginConfig,
      isPassword ? config.passwordLoginPath : config.loginPath,
      request.fields,
      { cookies: request.cookies },
    );
    request.cookies = mergeResponseCookies(request.cookies, response.headers);

    const { status, text, json, headers } = response;
    if (!json) throw new UpstreamError("上游返回了非 JSON 响应", { status });

    const challenge = await verification.challenge(json, action, client, request);
    if (challenge) {
      return { message: upstreamMessage(json, "请完成联通身份验证"), verification: challenge };
    }
    if (!isSuccessCode(json.code)) {
      throw new UpstreamError(upstreamMessage(json, "登录失败"), { status, raw: String(json.code) });
    }

    const ecsToken = json.ecs_token || readTokenFromCookies(headers, "ecs_token");
    const onlinToken = json.token_online || json.onlin_token || readTokenFromCookies(headers, "onlin_token");
    if (!ecsToken) throw new UpstreamError("上游未返回 ecs_token", { status, raw: text.slice(0, 200) });

    if (!request.cookies.ecs_token) request.cookies.ecs_token = ecsToken;
    return {
      ecsToken,
      onlinToken: onlinToken || "",
      desmobile: json.desmobile || "",
      cookie: cookieHeader(request.cookies),
    };
  }

  return {
    async sendSmsCode(client) {
      const { phone, deviceId } = client;
      const request = await verification.request("send", client, () => {
        const suffix = randomSixDigits();
        return {
          ...deviceFields(deviceId),
          mobile: encryptCredential(phone + suffix),
          send_flag: "",
          loginCodeLen: "6",
        };
      });

      const response = await postForm(loginConfig, config.sendSmsPath, request.fields, {
        cookies: request.cookies,
      });
      request.cookies = mergeResponseCookies(request.cookies, response.headers);
      const { text, json } = response;
      if (!json) throw new UpstreamError("上游返回了非 JSON 响应", { raw: text.slice(0, 200) });

      const challenge = await verification.challenge(json, "send", client, request);
      if (challenge) {
        return { ok: false, message: upstreamMessage(json, "请完成联通身份验证"), verification: challenge };
      }

      const ok = isSuccessCode(json.rsp_code ?? json.code);
      return { ok, message: upstreamMessage(json, ok ? "验证码已发送" : "发送失败") };
    },

    smsLogin: (client) => login("login", client),
    passwordLogin: (client) => login("password", client),

    queryOcs: (token, cookies) => query(config.ocsPath, token, normalizeOcs, cookies),
    queryBasicData: (token, cookies) => query(config.basicDataPath, token, normalizeBasicData, cookies),
    queryQci: (token, cookies) => query(config.qciPath, token, normalizeQci, cookies),
  };
}
