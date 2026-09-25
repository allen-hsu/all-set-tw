import { beforeEach, describe, expect, it, vi } from "vitest";
import forge from "node-forge";
import {
  completeSinopacHttpLogin,
  prepareSinopacHttpCaptcha,
  SinopacCaptchaRejectedError,
  SinopacProtocolError,
} from "@taiwan-fin-hub/connectors";

const puppeteerMock = vi.hoisted(() => ({
  connect: vi.fn(),
  launch: vi.fn(),
  limits: vi.fn(),
  sessions: vi.fn(),
}));
const jpegMock = vi.hoisted(() => ({
  decode: vi.fn(() => ({
    width: 1,
    height: 1,
    data: new Uint8Array([0, 0, 0, 255]),
  })),
}));

vi.mock("@cloudflare/puppeteer", () => ({ default: puppeteerMock }));
vi.mock("jpeg-js", () => jpegMock);

import {
  createSinopacConnector,
  loginSinopacWithHttpOcr,
  loginSinopacWithOcr,
  prepareSinopacCaptcha,
  SinopacBrowserCapacityError,
  SinopacCredentialRejectedError,
  SinopacVerificationRequiredError,
} from "../../src/connectors/sinopac";

const credentials = {
  userId: "A123456789",
  account: "test-user",
  password: "test-password",
};

function createLoginCertificate() {
  const keys = forge.pki.rsa.generateKeyPair(512);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = "01";
  certificate.validity.notBefore = new Date("2020-01-01T00:00:00Z");
  certificate.validity.notAfter = new Date("2030-01-01T00:00:00Z");
  const attributes = [{ name: "commonName", value: "sinopac.test" }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(certificate);
}

const TEST_LOGIN_CERTIFICATE = createLoginCertificate();

function loginPage(certificatePem: string) {
  return `<!doctype html>
    <form method="post" id="m_login" action="/m/member/login/m_login.aspx">
      <input name="dynamicCert" type="hidden" id="dynamic_hiddenCert" value="${certificatePem}" />
      <input name="dynamicTime" type="hidden" id="dynamic_hiddenServerTime" value="2026-09-25 12:00:00" />
      <input type="hidden" name="LoginWeb" value="Mobile" />
      <input type="hidden" name="source" value="MWeb" />
    </form>`;
}

function sinopacHttpFetch(
  options: {
    rejectCaptcha?: boolean;
    loginFlagMessage?: string;
    externalRedirect?: boolean;
  } = {},
) {
  const certificatePem = TEST_LOGIN_CERTIFICATE;
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fetcher = vi.fn(async function (
    this: unknown,
    input: RequestInfo | URL,
    init?: RequestInit,
  ) {
    expect(this).toBe(globalThis);
    const url = String(input);
    calls.push({ url, init });
    const method = init?.method ?? "GET";
    if (url.includes("m_login.aspx") && method === "GET") {
      return new Response(loginPage(certificatePem), {
        headers: {
          "Content-Type": "text/html",
          "Set-Cookie": "ASP.NET_SessionId=pending; Path=/; Secure; HttpOnly",
        },
      });
    }
    if (url.includes("ValidateNumber.ashx")) {
      return new Response(new Uint8Array([1, 2, 3]), {
        headers: { "Content-Type": "image/jpeg" },
      });
    }
    if (url.includes("ws_loginflag.ashx")) {
      return new Response(
        JSON.stringify([
          options.loginFlagMessage
            ? { Header: "FAIL", Message: options.loginFlagMessage }
            : { Header: "SUCCESS", IsLogin: "N", Message: "" },
        ]),
        { headers: { "Content-Type": "application/json" } },
      );
    }
    if (url.includes("m_login.aspx") && method === "POST") {
      if (options.rejectCaptcha) {
        return new Response(
          `<form id="m_login"></form><script>alert("驗證碼錯誤")</script>`,
          { headers: { "Content-Type": "text/html" } },
        );
      }
      return new Response(null, {
        status: options.externalRedirect ? 307 : 302,
        headers: {
          Location: options.externalRedirect
            ? "https://example.test/capture"
            : "/m/m_home.aspx",
          "Set-Cookie":
            "sinopac_cookie=authenticated; Path=/; Secure; HttpOnly",
        },
      });
    }
    if (url.endsWith("/m/m_home.aspx")) {
      return new Response("<main>home</main>", {
        headers: { "Content-Type": "text/html" },
      });
    }
    throw new Error(`Unexpected request: ${method} ${url}`);
  });
  return { calls, fetcher, certificatePem };
}

function captchaPage() {
  return {
    $: vi.fn().mockResolvedValue({
      screenshot: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    }),
    goto: vi.fn().mockResolvedValue(undefined),
    setUserAgent: vi.fn().mockResolvedValue(undefined),
    setViewport: vi.fn().mockResolvedValue(undefined),
    type: vi.fn().mockResolvedValue(undefined),
    url: vi
      .fn()
      .mockReturnValue(
        "https://m.sinopac.com/m/member/login/m_login.aspx?RequestTrans=MobileCard",
      ),
    waitForFunction: vi.fn().mockResolvedValue(undefined),
    waitForSelector: vi.fn().mockResolvedValue(undefined),
  };
}

function automaticLoginPage() {
  return {
    $: vi.fn().mockResolvedValue({
      screenshot: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    }),
    click: vi.fn().mockResolvedValue(undefined),
    cookies: vi
      .fn()
      .mockResolvedValue([
        { name: "ASP.NET_SessionId", value: "fresh-session" },
      ]),
    evaluate: vi.fn().mockResolvedValue(false),
    goto: vi.fn().mockResolvedValue(undefined),
    off: vi.fn(),
    once: vi.fn(),
    setUserAgent: vi.fn().mockResolvedValue(undefined),
    setViewport: vi.fn().mockResolvedValue(undefined),
    type: vi.fn().mockResolvedValue(undefined),
    url: vi
      .fn()
      .mockReturnValue(
        "https://m.sinopac.com/m/member/login/m_login.aspx?RequestTrans=MobileCard",
      ),
    waitForFunction: vi.fn().mockResolvedValue(undefined),
    waitForNavigation: vi.fn().mockResolvedValue(undefined),
    waitForSelector: vi.fn().mockResolvedValue(undefined),
  };
}

function launchedBrowser(page: ReturnType<typeof automaticLoginPage>) {
  return {
    close: vi.fn().mockResolvedValue(undefined),
    newPage: vi.fn().mockResolvedValue(page),
    pages: vi.fn().mockResolvedValue([page]),
    sessionId: vi.fn().mockReturnValue("auto-session"),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  puppeteerMock.sessions.mockResolvedValue([]);
  puppeteerMock.limits.mockResolvedValue({
    activeSessions: [],
    maxConcurrentSessions: 3,
    allowedBrowserAcquisitions: 1,
    timeUntilNextAllowedBrowserAcquisition: 0,
  });
});

describe("sinopac HTTP login lifecycle", () => {
  it("logs only safe transport metadata when the first HTTP request fails", async () => {
    const errorLog = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    const fetcher = vi
      .fn()
      .mockRejectedValue(
        new TypeError(
          "network failed for https://m.sinopac.com/private?password=secret",
        ),
      );

    try {
      await expect(
        prepareSinopacHttpCaptcha(credentials, fetcher),
      ).rejects.toThrow("連線暫時無法完成");

      const logged = String(errorLog.mock.calls[0]?.[0]);
      expect(logged).toContain('"event":"sinopac_http_request_failed"');
      expect(logged).toContain('"endpoint":"/m/member/login/m_login.aspx"');
      expect(logged).toContain('"errorName":"TypeError"');
      expect(logged).not.toContain("password=secret");
      expect(logged).not.toContain("m.sinopac.com");
    } finally {
      errorLog.mockRestore();
    }
  });

  it("prepares and completes a CAPTCHA login without acquiring Browser Run", async () => {
    const http = sinopacHttpFetch();
    const prepared = await prepareSinopacHttpCaptcha(credentials, http.fetcher);

    expect(prepared.captchaImage).toBe("data:image/jpeg;base64,AQID");
    expect(prepared.captchaDigitCount).toBe(6);
    expect(prepared.pendingSession).not.toContain(credentials.userId);
    expect(prepared.pendingSession).not.toContain(credentials.password);

    const result = await completeSinopacHttpLogin(
      {
        ...credentials,
        pendingSession: prepared.pendingSession,
        pendingSessionExpiresAt: prepared.pendingSessionExpiresAt,
      },
      "575831",
      http.fetcher,
    );

    expect(result.protocol).toBe("sinopac-mobile-app-json-v1");
    expect(JSON.parse(result.sessionCookies)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "ASP.NET_SessionId",
          value: "pending",
        }),
        expect.objectContaining({
          name: "sinopac_cookie",
          value: "authenticated",
        }),
      ]),
    );
    const loginFlag = http.calls.find(({ url }) =>
      url.includes("ws_loginflag.ashx"),
    );
    const flagBody = new URLSearchParams(String(loginFlag?.init?.body));
    expect(flagBody.get("CustId")).toBe(credentials.userId);
    expect(flagBody.get("UserCode")).not.toBe(credentials.account);
    expect(flagBody.get("UserCode")).toMatch(/\r\n$/);
    expect(flagBody.get("UserCode")?.replace(/\r\n/g, "")).toMatch(
      /^[A-Za-z0-9+/=]+$/,
    );
    expect(flagBody.get("UserPWD")).not.toContain(credentials.password);
    expect(flagBody.get("UserPWD")).toMatch(/\r\n$/);
    expect(flagBody.get("UserPWD")?.replace(/\r\n/g, "")).toMatch(
      /^[A-Za-z0-9+/=]+$/,
    );
    const loginPost = http.calls.find(
      ({ url, init }) =>
        url.includes("m_login.aspx") && init?.method === "POST",
    );
    const loginBody = new URLSearchParams(String(loginPost?.init?.body));
    expect(loginBody.get("UserCode")).not.toBe(credentials.account);
    expect(loginBody.get("UserPWD")).not.toBe(credentials.password);
    expect(loginBody.get("CheckValidateNumber")).toBe("575831");
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
    expect(puppeteerMock.connect).not.toHaveBeenCalled();
  });

  it("classifies a rejected HTTP CAPTCHA without retrying credentials", async () => {
    const http = sinopacHttpFetch({ rejectCaptcha: true });
    const prepared = await prepareSinopacHttpCaptcha(credentials, http.fetcher);

    await expect(
      completeSinopacHttpLogin(
        {
          ...credentials,
          pendingSession: prepared.pendingSession,
          pendingSessionExpiresAt: prepared.pendingSessionExpiresAt,
        },
        "000000",
        http.fetcher,
      ),
    ).rejects.toBeInstanceOf(SinopacCaptchaRejectedError);

    expect(
      http.calls.filter(({ url }) => url.includes("ws_loginflag.ashx")),
    ).toHaveLength(1);
  });

  it("automatically recognizes a fresh HTTP CAPTCHA without Browser Run", async () => {
    const http = sinopacHttpFetch();
    const recognize = vi.fn().mockResolvedValue("575831");

    await expect(
      loginSinopacWithHttpOcr(credentials, recognize, http.fetcher),
    ).resolves.toMatchObject({
      protocol: "sinopac-mobile-app-json-v1",
    });

    expect(recognize).toHaveBeenCalledOnce();
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
    expect(puppeteerMock.connect).not.toHaveBeenCalled();
  });

  it("fetches a new HTTP CAPTCHA after OCR output is invalid", async () => {
    const http = sinopacHttpFetch();
    const recognize = vi
      .fn()
      .mockRejectedValueOnce(new Error("unreadable"))
      .mockResolvedValueOnce("not-six-digits")
      .mockResolvedValueOnce("575831");

    await expect(
      loginSinopacWithHttpOcr(credentials, recognize, http.fetcher),
    ).resolves.toMatchObject({
      protocol: "sinopac-mobile-app-json-v1",
    });

    expect(recognize).toHaveBeenCalledTimes(3);
    expect(
      http.calls.filter(({ url }) => url.includes("ValidateNumber.ashx")),
    ).toHaveLength(3);
    expect(
      http.calls.filter(({ url }) => url.includes("ws_loginflag.ashx")),
    ).toHaveLength(1);
  });

  it("does not retry an HTTP login after explicit credential rejection", async () => {
    const http = sinopacHttpFetch({ loginFlagMessage: "網路密碼錯誤" });
    const recognize = vi.fn().mockResolvedValue("575831");

    await expect(
      loginSinopacWithHttpOcr(credentials, recognize, http.fetcher),
    ).rejects.toMatchObject({
      name: SinopacCredentialRejectedError.name,
      message: expect.stringContaining(
        "header=FAIL,isLogin=missing,reason=PASSWORD_ERROR,cookies=asp+no-sinopac",
      ),
    });

    expect(recognize).toHaveBeenCalledOnce();
    expect(
      http.calls.filter(({ url }) => url.includes("ws_loginflag.ashx")),
    ).toHaveLength(1);
    expect(
      http.calls.filter(
        ({ url, init }) =>
          url.includes("m_login.aspx") && init?.method === "POST",
      ),
    ).toHaveLength(0);
  });

  it("rejects a cross-origin redirect before forwarding cookies or credentials", async () => {
    const http = sinopacHttpFetch({ externalRedirect: true });
    const prepared = await prepareSinopacHttpCaptcha(credentials, http.fetcher);

    await expect(
      completeSinopacHttpLogin(
        {
          ...credentials,
          pendingSession: prepared.pendingSession,
          pendingSessionExpiresAt: prepared.pendingSessionExpiresAt,
        },
        "575831",
        http.fetcher,
      ),
    ).rejects.toBeInstanceOf(SinopacProtocolError);

    expect(
      http.calls.some(({ url }) => url.startsWith("https://example.test")),
    ).toBe(false);
  });
});

describe("sinopac browser session lifecycle", () => {
  it("requires one-time verification before acquiring a browser when no bank cookies exist", async () => {
    await expect(
      createSinopacConnector().sync(credentials),
    ).rejects.toBeInstanceOf(SinopacVerificationRequiredError);
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
  });

  it("reuses the exact pending captcha browser instead of launching another one", async () => {
    const page = captchaPage();
    const browser = {
      disconnect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      newPage: vi.fn().mockResolvedValue(page),
      pages: vi.fn().mockResolvedValue([page]),
      sessionId: vi.fn().mockReturnValue("pending-session"),
    };
    puppeteerMock.sessions.mockResolvedValue([
      { sessionId: "pending-session", startTime: Date.now() },
    ]);
    puppeteerMock.connect.mockResolvedValue(browser);

    const result = await prepareSinopacCaptcha({} as Fetcher, {
      ...credentials,
      browserSessionId: "pending-session",
    });

    expect(puppeteerMock.connect).toHaveBeenCalledWith({}, "pending-session");
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
    expect(browser.disconnect).toHaveBeenCalledOnce();
    expect(result.browserSessionId).toBe("pending-session");
    expect(result.captchaImage).toBe("data:image/jpeg;base64,AQID");
  });

  it("does not launch when the pending captcha browser is still connected", async () => {
    puppeteerMock.sessions.mockResolvedValue([
      {
        sessionId: "pending-session",
        startTime: Date.now(),
        connectionId: "busy-connection",
      },
    ]);

    await expect(
      prepareSinopacCaptcha({} as Fetcher, {
        ...credentials,
        browserSessionId: "pending-session",
      }),
    ).rejects.toBeInstanceOf(SinopacBrowserCapacityError);
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
  });

  it("returns a typed capacity error before launch when acquisition is rate limited", async () => {
    puppeteerMock.limits.mockResolvedValue({
      activeSessions: [],
      maxConcurrentSessions: 3,
      allowedBrowserAcquisitions: 0,
      timeUntilNextAllowedBrowserAcquisition: 20_000,
    });

    await expect(
      prepareSinopacCaptcha({} as Fetcher, credentials),
    ).rejects.toMatchObject({
      name: "SinopacBrowserCapacityError",
      retryAfterSeconds: 20,
    });
    expect(puppeteerMock.launch).not.toHaveBeenCalled();
  });
});

describe("sinopac Gemma automatic login", () => {
  it("uses a fresh captcha for each recognition failure and can succeed on attempt three", async () => {
    const page = automaticLoginPage();
    const browser = launchedBrowser(page);
    puppeteerMock.launch.mockResolvedValue(browser);
    const recognize = vi
      .fn()
      .mockRejectedValueOnce(new Error("unreadable"))
      .mockResolvedValueOnce("not-six-digits")
      .mockResolvedValueOnce("575831");

    await expect(
      loginSinopacWithOcr({} as Fetcher, credentials, recognize),
    ).resolves.toEqual({
      sessionCookies: JSON.stringify([
        { name: "ASP.NET_SessionId", value: "fresh-session" },
      ]),
      protocol: "sinopac-mobile-app-json-v1",
    });

    expect(recognize).toHaveBeenCalledTimes(3);
    expect(page.goto).toHaveBeenCalledTimes(3);
    expect(page.click).toHaveBeenCalledOnce();
    expect(browser.close).toHaveBeenCalledOnce();
  });

  it("stops after three failed captcha attempts", async () => {
    const page = automaticLoginPage();
    const browser = launchedBrowser(page);
    puppeteerMock.launch.mockResolvedValue(browser);
    const recognize = vi.fn().mockResolvedValue("invalid");

    await expect(
      loginSinopacWithOcr({} as Fetcher, credentials, recognize),
    ).rejects.toThrow("連續失敗 3 次");

    expect(recognize).toHaveBeenCalledTimes(3);
    expect(page.goto).toHaveBeenCalledTimes(3);
    expect(browser.close).toHaveBeenCalledOnce();
  });

  it("reloads a new captcha after bank rejection and succeeds on attempt three", async () => {
    const page = automaticLoginPage();
    page.evaluate
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce("驗證碼錯誤")
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce("驗證碼有誤")
      .mockResolvedValueOnce(false);
    const browser = launchedBrowser(page);
    puppeteerMock.launch.mockResolvedValue(browser);
    const recognize = vi.fn().mockResolvedValue("575831");

    await expect(
      loginSinopacWithOcr({} as Fetcher, credentials, recognize),
    ).resolves.toMatchObject({
      protocol: "sinopac-mobile-app-json-v1",
    });

    expect(recognize).toHaveBeenCalledTimes(3);
    expect(page.goto).toHaveBeenCalledTimes(3);
    expect(page.click).toHaveBeenCalledTimes(3);
  });

  it("does not retry when the bank explicitly rejects the credentials", async () => {
    const page = automaticLoginPage();
    page.evaluate.mockResolvedValueOnce(true).mockResolvedValueOnce("密碼錯誤");
    const browser = launchedBrowser(page);
    puppeteerMock.launch.mockResolvedValue(browser);
    const recognize = vi.fn().mockResolvedValue("575831");

    await expect(
      loginSinopacWithOcr({} as Fetcher, credentials, recognize),
    ).rejects.toBeInstanceOf(SinopacCredentialRejectedError);

    expect(recognize).toHaveBeenCalledOnce();
    expect(page.goto).toHaveBeenCalledOnce();
    expect(browser.close).toHaveBeenCalledOnce();
  });
});
