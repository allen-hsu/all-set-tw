import forge from "node-forge";
import type { SinopacConfig } from "./sinopac";

const SINOPAC_ORIGIN = "https://m.sinopac.com";
const LOGIN_URL = `${SINOPAC_ORIGIN}/m/member/login/m_login.aspx?RequestTrans=MobileCard`;
const LOGIN_FLAG_URL = `${SINOPAC_ORIGIN}/ws/member/login/ws_loginflag.ashx`;
const CAPTCHA_URL = `${SINOPAC_ORIGIN}/Share/OnlineService/ValidateNumber.ashx`;
const LOGIN_REFERER = LOGIN_URL;
const PENDING_SESSION_TTL_MS = 2 * 60_000;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;

export const SINOPAC_SESSION_PROTOCOL = "sinopac-mobile-app-json-v1";
export const SINOPAC_CAPTCHA_DIGIT_COUNT = 6;
export const SINOPAC_HTTP_USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/UP1A.231105.003) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

export type SinopacFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type SinopacCredentials = Required<
  Pick<SinopacConfig, "userId" | "account" | "password">
>;

type PendingSessionState = {
  version: 1;
  cookies: Record<string, string>;
  formAction: string;
  hiddenFields: Record<string, string>;
  certificatePem: string;
  serverTime: string;
};

export type SinopacCaptchaChallenge = {
  captchaImage: string;
  contentType: string;
  imageBytes: ArrayBuffer;
  pendingSession: string;
  pendingSessionExpiresAt: string;
  captchaDigitCount: typeof SINOPAC_CAPTCHA_DIGIT_COUNT;
};

export type SinopacLoginSession = {
  sessionCookies: string;
  protocol: typeof SINOPAC_SESSION_PROTOCOL;
};

export class SinopacVerificationRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SinopacVerificationRequiredError";
  }
}

export class SinopacCaptchaRejectedError extends SinopacVerificationRequiredError {
  constructor(message = "永豐銀行圖形驗證碼錯誤，請重新取得驗證碼。") {
    super(message);
    this.name = "SinopacCaptchaRejectedError";
  }
}

export class SinopacCredentialRejectedError extends SinopacVerificationRequiredError {
  constructor(
    message = "永豐銀行拒絕登入，請確認身分證字號、使用者代碼與網路密碼。",
  ) {
    super(message);
    this.name = "SinopacCredentialRejectedError";
  }
}

export class SinopacConnectionError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "SinopacConnectionError";
    if (cause !== undefined) this.cause = cause;
  }
}

export class SinopacProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SinopacProtocolError";
  }
}

export function requireSinopacCredentials(
  config: Pick<SinopacConfig, "userId" | "account" | "password">,
): SinopacCredentials {
  if (!config.userId || !config.account || !config.password) {
    throw new SinopacVerificationRequiredError(
      "請先儲存永豐身分證字號／統編、使用者代碼與網路密碼。",
    );
  }
  return {
    userId: config.userId,
    account: config.account,
    password: config.password,
  };
}

export async function prepareSinopacHttpCaptcha(
  config: SinopacConfig,
  fetcher: SinopacFetch = globalThis.fetch.bind(globalThis),
): Promise<SinopacCaptchaChallenge> {
  requireSinopacCredentials(config);
  const session = new SinopacLoginHttpSession(fetcher);
  await session.openLoginPage();
  const captcha = await session.fetchCaptcha();
  return {
    captchaImage: `data:${captcha.contentType};base64,${bytesToBase64(captcha.bytes)}`,
    contentType: captcha.contentType,
    imageBytes: captcha.bytes,
    pendingSession: session.serialize(),
    pendingSessionExpiresAt: new Date(
      Date.now() + PENDING_SESSION_TTL_MS,
    ).toISOString(),
    captchaDigitCount: SINOPAC_CAPTCHA_DIGIT_COUNT,
  };
}

export async function completeSinopacHttpLogin(
  config: SinopacConfig,
  captcha: string,
  fetcher: SinopacFetch = globalThis.fetch.bind(globalThis),
): Promise<SinopacLoginSession> {
  const credentials = requireSinopacCredentials(config);
  if (
    !config.pendingSession ||
    !config.pendingSessionExpiresAt ||
    new Date(config.pendingSessionExpiresAt) <= new Date()
  ) {
    throw new SinopacVerificationRequiredError(
      "永豐圖形驗證碼已逾時，請重新取得驗證碼。",
    );
  }
  if (!new RegExp(`^\\d{${SINOPAC_CAPTCHA_DIGIT_COUNT}}$`).test(captcha)) {
    throw new SinopacCaptchaRejectedError(
      `永豐驗證碼必須是 ${SINOPAC_CAPTCHA_DIGIT_COUNT} 位數字。`,
    );
  }
  const session = SinopacLoginHttpSession.deserialize(
    config.pendingSession,
    fetcher,
  );
  await session.login(credentials, captcha);
  return {
    sessionCookies: session.exportCookies(),
    protocol: SINOPAC_SESSION_PROTOCOL,
  };
}

export function encryptSinopacCredential(
  certificatePem: string,
  password: string,
  serverTime: string,
) {
  try {
    const certificate = forge.pki.certificateFromPem(certificatePem);
    const message = forge.pkcs7.createEnvelopedData();
    message.content = forge.util.createBuffer(
      `${password}${serverTime}`,
      "utf8",
    );
    message.addRecipient(certificate);
    message.encrypt();
    const pem = forge.pkcs7.messageToPem(
      message as unknown as Parameters<typeof forge.pkcs7.messageToPem>[0],
    );
    const lines = pem.trim().split(/\r?\n/);
    return `${lines.slice(1, -1).join("\r\n")}\r\n`;
  } catch (error) {
    throw new SinopacProtocolError(
      `永豐登入憑證無法處理：${safeErrorName(error)}。`,
    );
  }
}

export function classifySinopacLoginMessage(message: string) {
  const normalized = message.replace(/\s+/g, " ").trim();
  if (/驗證碼.*(?:錯誤|有誤|失效|逾時)/.test(normalized)) {
    return "captcha" as const;
  }
  if (
    /密碼.*(?:錯誤|有誤)|使用者代(?:碼|號).*(?:錯誤|有誤)|帳號.*(?:錯誤|有誤)|身分證.*(?:錯誤|有誤)|MemberNotActivated/i.test(
      normalized,
    )
  ) {
    return "credential" as const;
  }
  return "unknown" as const;
}

class SinopacLoginHttpSession {
  private readonly cookies = new Map<string, string>();
  private formAction = "/m/member/login/m_login.aspx";
  private hiddenFields: Record<string, string> = {};
  private certificatePem = "";
  private serverTime = "";

  constructor(private readonly fetcher: SinopacFetch) {}

  static deserialize(serialized: string, fetcher: SinopacFetch) {
    let state: PendingSessionState;
    try {
      state = JSON.parse(serialized) as PendingSessionState;
    } catch {
      throw new SinopacProtocolError("永豐待驗證 session 格式無效。");
    }
    if (
      state.version !== 1 ||
      !state.cookies ||
      !state.formAction ||
      !state.certificatePem ||
      !state.serverTime
    ) {
      throw new SinopacProtocolError("永豐待驗證 session 內容不完整。");
    }
    const session = new SinopacLoginHttpSession(fetcher);
    for (const [name, value] of Object.entries(state.cookies)) {
      if (name && typeof value === "string") session.cookies.set(name, value);
    }
    session.formAction = state.formAction;
    session.hiddenFields = { ...state.hiddenFields };
    session.certificatePem = state.certificatePem;
    session.serverTime = state.serverTime;
    return session;
  }

  serialize() {
    return JSON.stringify({
      version: 1,
      cookies: Object.fromEntries(this.cookies),
      formAction: this.formAction,
      hiddenFields: this.hiddenFields,
      certificatePem: this.certificatePem,
      serverTime: this.serverTime,
    } satisfies PendingSessionState);
  }

  exportCookies() {
    return JSON.stringify(
      Array.from(this.cookies, ([name, value]) => ({
        name,
        value,
        domain: "m.sinopac.com",
        path: "/",
      })),
    );
  }

  async openLoginPage() {
    const response = await this.request(LOGIN_URL, {
      headers: { Accept: "text/html,application/xhtml+xml" },
    });
    if (!response.ok) {
      throw new SinopacConnectionError(
        `永豐登入頁回應 HTTP ${response.status}。`,
      );
    }
    const html = await response.text();
    const parsed = parseLoginPage(html);
    this.formAction = parsed.formAction;
    this.hiddenFields = parsed.hiddenFields;
    this.certificatePem = parsed.certificatePem;
    this.serverTime = parsed.serverTime;
  }

  async fetchCaptcha() {
    const response = await this.request(`${CAPTCHA_URL}?${Date.now()}`, {
      headers: {
        Accept: "image/avif,image/webp,image/apng,image/jpeg,*/*;q=0.8",
        Referer: LOGIN_REFERER,
      },
    });
    if (!response.ok) {
      throw new SinopacConnectionError(
        `永豐驗證碼回應 HTTP ${response.status}。`,
      );
    }
    const contentType = response.headers.get("content-type")?.split(";")[0];
    if (!contentType?.startsWith("image/")) {
      throw new SinopacProtocolError("永豐驗證碼 API 沒有回傳圖片。");
    }
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength === 0) {
      throw new SinopacProtocolError("永豐驗證碼圖片是空白內容。");
    }
    return { contentType, bytes };
  }

  async login(credentials: SinopacCredentials, captcha: string) {
    const encryptedUserCode = encryptSinopacCredential(
      this.certificatePem,
      credentials.account,
      this.serverTime,
    );
    const encryptedPassword = encryptSinopacCredential(
      this.certificatePem,
      credentials.password,
      this.serverTime,
    );
    console.info(
      JSON.stringify({
        event: "sinopac_login_request_ready",
        cookieCount: this.cookies.size,
        hasAspNetSession: this.cookies.has("ASP.NET_SessionId"),
        hasSinopacCookie: this.cookies.has("sinopac_cookie"),
        userCodeLength: encryptedUserCode.length,
        passwordLength: encryptedPassword.length,
        userCodeCrlf: countCrlf(encryptedUserCode),
        passwordCrlf: countCrlf(encryptedPassword),
        serverTimeFormatValid: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(
          this.serverTime,
        ),
      }),
    );
    const loginFlag = await this.postForm(LOGIN_FLAG_URL, {
      CustId: credentials.userId,
      UserCode: encryptedUserCode,
      UserPWD: encryptedPassword,
      source: "MWeb",
    });
    const flagPayload = await readLoginFlag(loginFlag);
    console.info(
      JSON.stringify({
        event: "sinopac_login_precheck_result",
        header: flagPayload.header,
        isLogin: flagPayload.isLogin,
        outcome: classifySinopacLoginMessage(flagPayload.message),
        message: safeLoginMessage(flagPayload.message),
      }),
    );
    if (flagPayload.isLogin !== "Y" && flagPayload.isLogin !== "N") {
      throw classifiedLoginError(
        flagPayload.message,
        [
          `header=${flagPayload.header || "missing"}`,
          `isLogin=${flagPayload.isLogin || "missing"}`,
          `reason=${sinopacCredentialReason(flagPayload.message)}`,
          `cookies=${this.cookies.has("ASP.NET_SessionId") ? "asp" : "no-asp"}+${this.cookies.has("sinopac_cookie") ? "sinopac" : "no-sinopac"}`,
          `crypto=${encryptedUserCode.length}/${countCrlf(encryptedUserCode)}:${encryptedPassword.length}/${countCrlf(encryptedPassword)}`,
        ].join(","),
      );
    }

    const loginUrl = new URL(this.formAction, SINOPAC_ORIGIN);
    if (loginUrl.origin !== SINOPAC_ORIGIN) {
      throw new SinopacProtocolError("永豐登入表單指向未授權的網站。");
    }
    const response = await this.postForm(loginUrl.toString(), {
      ...this.hiddenFields,
      LoginWeb: "Mobile",
      CustId: credentials.userId,
      UserCode: encryptedUserCode,
      UserPWD: encryptedPassword,
      source: "MWeb",
      pushEnabler: "",
      CheckValidateNumber: captcha,
    });
    const html = await response.text();
    if (isLoginPage(response.url, html)) {
      throw classifiedLoginError(loginFailureMessage(html));
    }
  }

  private postForm(url: string, fields: Record<string, string>) {
    const isPrecheck = url === LOGIN_FLAG_URL;
    return this.request(url, {
      method: "POST",
      headers: {
        Accept: isPrecheck
          ? "application/json, text/javascript, */*; q=0.01"
          : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Content-Type": isPrecheck
          ? "application/x-www-form-urlencoded; charset=UTF-8"
          : "application/x-www-form-urlencoded",
        Origin: SINOPAC_ORIGIN,
        Referer: LOGIN_REFERER,
        "X-Requested-With": isPrecheck ? "XMLHttpRequest" : "",
      },
      body: new URLSearchParams(fields).toString(),
    });
  }

  private async request(url: string, init: RequestInit = {}) {
    let nextUrl = url;
    let nextInit = init;
    for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
      const headers = new Headers(nextInit.headers);
      headers.set("User-Agent", SINOPAC_HTTP_USER_AGENT);
      const cookie = Array.from(
        this.cookies,
        ([name, value]) => `${name}=${value}`,
      ).join("; ");
      if (cookie) headers.set("Cookie", cookie);
      if (!headers.get("X-Requested-With")) headers.delete("X-Requested-With");
      let response: Response;
      try {
        response = await this.fetcher.call(globalThis, nextUrl, {
          ...nextInit,
          headers,
          redirect: "manual",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "sinopac_http_request_failed",
            endpoint: safeEndpoint(nextUrl),
            method: nextInit.method ?? "GET",
            errorName: safeErrorName(error),
            message: safeTransportMessage(error),
          }),
        );
        throw new SinopacConnectionError("永豐銀行連線暫時無法完成。", error);
      }
      storeResponseCookies(this.cookies, response.headers);
      if (![301, 302, 303, 307, 308].includes(response.status)) return response;
      const location = response.headers.get("location");
      if (!location) return response;
      if (redirect === MAX_REDIRECTS) {
        throw new SinopacProtocolError("永豐登入重新導向次數過多。");
      }
      const redirectUrl = new URL(location, nextUrl);
      if (redirectUrl.origin !== SINOPAC_ORIGIN) {
        throw new SinopacProtocolError("永豐登入嘗試重新導向至未授權的網站。");
      }
      nextUrl = redirectUrl.toString();
      if ([301, 302, 303].includes(response.status)) {
        const redirectedHeaders = new Headers(nextInit.headers);
        redirectedHeaders.delete("Content-Type");
        redirectedHeaders.delete("Origin");
        redirectedHeaders.delete("X-Requested-With");
        nextInit = { method: "GET", headers: redirectedHeaders };
      }
    }
    throw new SinopacProtocolError("永豐登入重新導向無法完成。");
  }
}

function parseLoginPage(html: string) {
  const pageInputs = parseInputs(html);
  const certificatePem = findInputValue(pageInputs, "hiddenCert");
  const serverTime = findInputValue(pageInputs, "hiddenServerTime");
  const formMatch = html.match(
    /(<form\b(?=[^>]*\bid=["']m_login["'])[^>]*>)[\s\S]*?<\/form>/i,
  );
  const formAction = formMatch?.[1].match(/\baction=["']([^"']+)["']/i)?.[1];
  if (!certificatePem || !serverTime || !formAction || !formMatch) {
    throw new SinopacProtocolError("永豐登入頁缺少加密憑證或表單資訊。");
  }
  const hiddenFields: Record<string, string> = {};
  for (const input of parseInputs(formMatch[0])) {
    if (input.name) {
      hiddenFields[input.name] = input.value;
    }
  }
  return {
    certificatePem,
    serverTime,
    formAction: decodeHtml(formAction),
    hiddenFields,
  };
}

function parseInputs(html: string) {
  return Array.from(html.matchAll(/<input\b[^>]*>/gi), ([tag]) => {
    const attributes: Record<string, string> = {};
    for (const match of tag.matchAll(
      /([^\s=<>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g,
    )) {
      attributes[match[1]!.toLowerCase()] = decodeHtml(
        match[2] ?? match[3] ?? match[4] ?? "",
      );
    }
    return {
      id: attributes.id ?? "",
      name: attributes.name ?? "",
      type: attributes.type ?? "",
      value: attributes.value ?? "",
    };
  });
}

function findInputValue(
  inputs: ReturnType<typeof parseInputs>,
  suffix: string,
) {
  return inputs.find(
    (input) => input.id.endsWith(suffix) || input.name.endsWith(suffix),
  )?.value;
}

async function readLoginFlag(response: Response) {
  if (!response.ok) {
    throw new SinopacConnectionError(
      `永豐登入檢查回應 HTTP ${response.status}。`,
    );
  }
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new SinopacProtocolError("永豐登入檢查沒有回傳有效 JSON。");
  }
  const item = Array.isArray(payload) ? payload[0] : undefined;
  if (!item || typeof item !== "object") {
    throw new SinopacProtocolError("永豐登入檢查回應格式無法辨識。");
  }
  const record = item as Record<string, unknown>;
  return {
    header: typeof record.Header === "string" ? record.Header : "",
    isLogin: typeof record.IsLogin === "string" ? record.IsLogin : "",
    message: typeof record.Message === "string" ? record.Message : "",
  };
}

function countCrlf(value: string) {
  return value.match(/\r\n/g)?.length ?? 0;
}

function classifiedLoginError(message: string, diagnostic?: string): Error {
  const outcome = classifySinopacLoginMessage(message);
  if (outcome === "captcha") return new SinopacCaptchaRejectedError();
  if (outcome === "credential") {
    return new SinopacCredentialRejectedError(
      `永豐銀行拒絕登入，請確認身分證字號、使用者代碼與網路密碼${diagnostic ? `（${diagnostic}）` : "。"}`,
    );
  }
  return new SinopacVerificationRequiredError(
    `永豐銀行登入失敗：${safeLoginMessage(message) || "請重新驗證"}${diagnostic ? `（${diagnostic}）` : ""}`,
  );
}

function sinopacCredentialReason(message: string) {
  const normalized = message.replace(/\s+/g, " ");
  if (/MemberNotActivated/i.test(normalized)) return "NOT_ACTIVATED";
  if (/使用者代(?:碼|號).*(?:錯誤|有誤)/.test(normalized)) {
    return "USER_CODE_ERROR";
  }
  if (/密碼.*(?:錯誤|有誤)/.test(normalized)) return "PASSWORD_ERROR";
  if (/身分證.*(?:錯誤|有誤)/.test(normalized)) return "USER_ID_ERROR";
  if (/帳號.*(?:錯誤|有誤)/.test(normalized)) return "ACCOUNT_ERROR";
  return "CREDENTIAL_ERROR";
}

function isLoginPage(url: string, html: string) {
  return (
    /\/m\/member\/login\/m_login\.aspx/i.test(url) ||
    /<form\b[^>]*\bid=["']m_login["']/i.test(html)
  );
}

function loginFailureMessage(html: string) {
  const decoded = decodeHtml(html).replace(/\\[nrt]/g, " ");
  const known = decoded.match(
    /.{0,80}(?:驗證碼.*(?:錯誤|有誤|失效|逾時)|密碼.*(?:錯誤|有誤)|使用者代(?:碼|號).*(?:錯誤|有誤)|帳號.*(?:錯誤|有誤)|身分證.*(?:錯誤|有誤)|MemberNotActivated).{0,120}/i,
  )?.[0];
  if (known) return known.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  return decoded
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function storeResponseCookies(cookies: Map<string, string>, headers: Headers) {
  const cookieHeaders = getSetCookieHeaders(headers);
  for (const header of cookieHeaders) {
    const pair = header.split(";", 1)[0]?.trim();
    const separator = pair?.indexOf("=") ?? -1;
    if (!pair || separator <= 0) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1);
    if (/max-age=0|expires=Thu, 01 Jan 1970/i.test(header)) {
      cookies.delete(name);
    } else {
      cookies.set(name, value);
    }
  }
}

function getSetCookieHeaders(headers: Headers) {
  const extended = headers as Headers & { getSetCookie?: () => string[] };
  const separate = extended.getSetCookie?.();
  if (separate?.length) return separate;
  const combined = headers.get("set-cookie");
  return combined
    ? combined.split(/,(?=\s*[^;,=\s]+=[^;,]*)/g).map((value) => value.trim())
    : [];
}

function bytesToBase64(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeHtml(value: string) {
  return value
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .replace(/&#(\d+);/g, (_match, code: string) =>
      String.fromCodePoint(Number(code)),
    );
}

function safeLoginMessage(message: string) {
  return message
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[URL]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}

function safeErrorName(error: unknown) {
  return error instanceof Error ? error.name : "UNKNOWN_ERROR";
}

function safeEndpoint(value: string) {
  try {
    return new URL(value).pathname;
  } catch {
    return "unknown";
  }
}

function safeTransportMessage(error: unknown) {
  return (error instanceof Error ? error.message : String(error))
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[URL]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
}
