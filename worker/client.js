export class UpstreamError extends Error {
  constructor(message, { status = 0, raw = "" } = {}) {
    super(message);
    this.name = "UpstreamError";
    this.status = status;
    this.raw = raw;
  }
}

export function buildUserAgent(config, desmobile = "") {
  const { androidVersion, deviceModel, deviceBrand, appVersion } = config;
  return `Mozilla/5.0 (Linux; Android ${androidVersion}; ${deviceModel} Build/SP1A.210812.016; wv) `
    + "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/103.0.5060.129 Mobile Safari/537.36; "
    + `unicom{version:${appVersion},desmobile:${desmobile}};`
    + `devicetype{deviceBrand:${deviceBrand},deviceModel:${deviceModel}};{yw_code:}`;
}

function encodeForm(fields) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined || value === null) continue;
    params.set(key, String(value));
  }
  return params.toString();
}

export async function postForm(config, path, fields, { desmobile = "", cookies = {} } = {}) {
  const url = new URL(path, config.baseUrl);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new UpstreamError("上游协议必须是 HTTP 或 HTTPS");
  }
  if (url.origin !== new URL(config.baseUrl).origin) {
    throw new UpstreamError("上游路径不能指向其他服务");
  }
  for (const value of Object.values(cookies)) {
    if (value && (typeof value !== "string" || /[^\x21-\x7e]|[;",\\]/.test(value))) {
      throw new UpstreamError("Token 格式错误");
    }
  }

  const cookieHeader = Object.entries(cookies)
    .filter(([, value]) => value)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const body = encodeForm(fields);
    const response = await fetch(url.toString(), {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": buildUserAgent(config, desmobile),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        Accept: "application/json, text/plain, */*",
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
      body,
    });

    const status = response.status;
    if (status >= 300 && status < 400) {
      throw new UpstreamError("上游拒绝了请求（可能是地域或风控拦截）", { status });
    }
    if (status < 200 || status >= 300) {
      throw new UpstreamError(`上游服务异常（HTTP ${status}）`, { status });
    }

    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > 2 * 1024 * 1024) {
      throw new UpstreamError("上游响应过大", { status });
    }

    let json = null;
    try {
      const value = JSON.parse(text);
      if (value && typeof value === "object" && !Array.isArray(value)) json = value;
    } catch {
      // ignore non-JSON
    }

    return { status, text, json, headers: response.headers };
  } catch (cause) {
    if (cause instanceof UpstreamError) throw cause;
    throw new UpstreamError(controller.signal.aborted ? "上游请求超时" : "上游请求失败");
  } finally {
    clearTimeout(timer);
  }
}
