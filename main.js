var _ = Object.defineProperty;
var D = (n, e, o) => e in n ? _(n, e, { enumerable: !0, configurable: !0, writable: !0, value: o }) : n[e] = o;
var h = (n, e, o) => D(n, typeof e != "symbol" ? e + "" : e, o);
const m = {
  LOGOUT: "memberstack.logout",
  GET_APP: "memberstack.getApp",
  LOGIN: "memberstack.login",
  VALID_SESSION: "memberstack.validSession",
  SIGN_UP: "memberstack.signUp"
};
function T(n) {
  if (!n)
    throw new Error("Memberstack instance is not defined");
  window._msConfig || (window._msConfig = {
    preventLogin: !0
  }), window.$memberstackDom = new Proxy(n, {
    get(e, o) {
      const t = e[o];
      return typeof t == "function" ? async function(...a) {
        if (console.log(
          `Method ${o} called with arguments: ${JSON.stringify(a)}`
        ), o === "logout") {
          const i = new CustomEvent(m.LOGOUT, {
            bubbles: !1,
            cancelable: !1,
            detail: a[0]
          });
          return document.dispatchEvent(i), !1;
        }
        if (o === "getApp") {
          const i = new Event(m.GET_APP, {
            bubbles: !1,
            cancelable: !1
          });
          document.dispatchEvent(i);
        }
        if (o === "loginMemberEmailPassword") {
          const i = new CustomEvent(m.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: a[0]
          });
          return document.dispatchEvent(i), {
            data: {}
          };
        }
        if (o === "loginWithProvider") {
          const i = await t.apply(e, a), c = new CustomEvent(m.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: i
          });
          return document.dispatchEvent(c), i;
        }
        if (o === "signupWithProvider") {
          const i = await t.apply(e, a), c = new CustomEvent(m.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: i
          });
          return document.dispatchEvent(c), i;
        }
        if (o === "signupMemberEmailPassword") {
          const i = await t.apply(e, a), c = new CustomEvent(m.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: i
          });
          return document.dispatchEvent(c), i;
        }
        return t.apply(e, a);
      } : t;
    }
  });
}
function A() {
  const n = "_ga_7T2LX34911", e = document.cookie.split("; ");
  for (const o of e) {
    const [t, a] = o.split("=");
    if (t === n)
      return a;
  }
  throw new Error("Device Id cookie not found");
}
const L = "https://staging-api.ordotype.fr/v1.0.0";
class b extends Error {
  constructor(o, t = 500) {
    super(o);
    h(this, "status");
    this.name = "AuthError", this.status = t, Error.captureStackTrace && Error.captureStackTrace(this, b);
  }
}
class E extends Error {
  constructor(o, t, a) {
    super(o);
    h(this, "data");
    h(this, "type");
    this.name = "TwoFactorRequiredError", this.data = t, this.type = a;
  }
}
class I {
  constructor() {
    h(this, "headers");
    const e = "pk_sb_e80d8429a51c2ceb0530", o = window.localStorage.getItem("ms_session_id"), t = A();
    this.headers = {
      "X-Api-Key": e,
      "X-Session-Id": o ?? void 0,
      "X-Device-Id": t ?? void 0
    };
  }
  async request(e, o, t = "GET", a = null, i = {}) {
    const c = `${L}/${o}/${e}`, p = {
      "Content-Type": "application/json",
      ...this.headers,
      ...i
    }, v = {
      method: t,
      headers: p,
      ...a && { body: JSON.stringify(a) }
    };
    try {
      const d = await fetch(c, v);
      if (!d.ok)
        throw new b(d.statusText, d.status);
      return d.status === 204 || !d.body ? null : await d.json();
    } catch (d) {
      throw console.error("API Request Failed:", d), d;
    }
  }
  async validateSessionStatus() {
    try {
      const e = localStorage.getItem("_ms-mid");
      return await this.request(
        "validate-session-status",
        "auth",
        "POST",
        null,
        { Authorization: `Bearer ${e}` }
      );
    } catch (e) {
      throw console.error("Session validation failed:", e), e;
    }
  }
  async logout() {
    try {
      const e = localStorage.getItem("_ms-mid");
      await this.request(
        "logout",
        "auth",
        "POST",
        null,
        { Authorization: `Bearer ${e}` }
      ), localStorage.removeItem("_ms-mid");
    } catch (e) {
      throw console.error("Session logout failed:", e), e;
    }
  }
  async signup(e) {
    const o = {
      ...e,
      device: this.headers["X-Device-Id"] ?? "unknown"
    };
    return await this.request(
      "signup",
      "auth",
      "POST",
      o,
      {}
    );
  }
  async login(e) {
    const o = {
      ...e,
      options: {
        includeContentGroups: !0,
        isWebflow: !0
      },
      device: this.headers["X-Device-Id"] ?? "unknown"
    }, t = await this.request(
      "login",
      "auth",
      "POST",
      o,
      {}
    );
    if (y(t))
      throw new E("2fa required", t.data, t.type);
    return t;
  }
  async loginWithProvider(e) {
    const o = {
      ...e,
      device: this.headers["X-Device-Id"] ?? "unknown"
    }, t = await this.request(
      "validate-google-provider",
      "auth",
      "POST",
      o,
      {}
    );
    if (y(t))
      throw new E("2fa required", t.data, t.type);
    return t;
  }
  // Helper to get a cookie
  getCookie(e) {
    const o = document.cookie.match(new RegExp(`(^| )${e}=([^;]+)`));
    return o ? decodeURIComponent(o[2]) : null;
  }
  // Helper to set a cookie with expiration time
  setCookie(e, o, t) {
    const a = /* @__PURE__ */ new Date();
    a.setTime(a.getTime() + t), document.cookie = `${e}=${encodeURIComponent(o)}; expires=${a.toUTCString()}; path=/`;
  }
  // Reusable throttle function
  async throttle(e, o, t) {
    const a = this.getCookie(o), i = Date.now();
    if (a && i - parseInt(a, 10) < t)
      return console.log(`Skipping execution of ${o}: Throttled.`), null;
    console.log(`Executing ${o}...`);
    const c = await e();
    return this.setCookie(o, i.toString(), t), c;
  }
  // Public wrapper for validateSessionStatus with throttling
  validateSessionStatusThrottled() {
    return localStorage.getItem("_ms-mid") ? this.throttle(
      () => this.validateSessionStatus(),
      "lastSessionValidation",
      3 * 60 * 1e3
      // 3 minutes throttle interval
    ) : Promise.resolve(null);
  }
}
function y(n) {
  return "data" in n && typeof n.data == "object" && "type" in n;
}
new I();
function S() {
  return !!localStorage.getItem("_ms-mid");
}
function k(n) {
  window.$memberstackDom._showLoader(), setTimeout(() => {
    window.location.href = n;
  }, 500);
}
const $ = async (n, e = "/") => {
  await window.$memberstackDom.logout(), localStorage.removeItem("_ms-mid"), localStorage.removeItem("_ms_mem"), k(e);
}, P = (n) => {
  const e = new CustomEvent(m.VALID_SESSION, {
    bubbles: !1,
    cancelable: !1,
    detail: { isStatusValid: n }
  });
  document.dispatchEvent(e);
};
function O() {
  var v, d;
  function n(s) {
    return "provider" in s;
  }
  function e(s) {
    return "email" in s && "password" in s;
  }
  function o(s) {
    const r = {};
    return s.querySelectorAll("[data-ms-member]").forEach((u) => {
      const w = u.getAttribute("data-ms-member");
      w && !["email", "password", "new-password", "current-password"].includes(w) && (r[w] = u.value || "");
    }), r;
  }
  function t(s) {
    const r = s.getAttribute("data-ms-plan") || s.getAttribute("data-ms-plan:add") || s.getAttribute("data-ms-plan:update"), l = s.getAttribute("data-ms-price:add");
    return { freePlan: r, paidPlan: l };
  }
  async function a(s, r) {
    console.error(s, r), await window.$memberstackDom._showMessage((r == null ? void 0 : r.message) || "An error occurred", !0);
  }
  async function i(s, r) {
    var g, f;
    s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation();
    const l = s.target, u = (g = l.querySelector('[data-ms-member="email"]')) == null ? void 0 : g.value, w = (f = l.querySelector('[data-ms-member="password"]')) == null ? void 0 : f.value;
    r === "signup" ? await p(l, { email: u, password: w }) : r === "login" && await c(l, { email: u, password: w });
  }
  async function c(s, r) {
    let l;
    if (n(r))
      l = {
        provider: r.provider
      };
    else if (e(r))
      l = {
        email: r.email,
        password: r.password
      };
    else
      throw new Error("Invalid form authentication options");
    try {
      const u = n(r) ? await window.$memberstackDom.loginWithProvider(l) : await window.$memberstackDom.loginMemberEmailPassword(l);
      console.log("Signin successful:", u);
    } catch (u) {
      await a("Login failed:", u);
    }
  }
  async function p(s, r) {
    const l = o(s), { freePlan: u, paidPlan: w } = t(s);
    let g = { customFields: l };
    if (n(r))
      g = {
        allowLogin: !1,
        provider: r.provider
      };
    else if (e(r))
      g = {
        email: r.email,
        password: r.password
      };
    else
      throw new Error("Invalid form authentication options");
    u && (g.plans = [{ planId: u }]);
    try {
      window.$memberstackDom._showLoader();
      const f = n(r) ? await window.$memberstackDom.signupWithProvider(g) : await window.$memberstackDom.signupMemberEmailPassword(g);
      console.log("Signup successful:", f), w ? await window.$memberstackDom.purchasePlansWithCheckout({ priceId: w }) : k(f.data.redirect), window.$memberstackDom._hideLoader();
    } catch (f) {
      await a("Signup failed:", f), window.$memberstackDom._hideLoader();
    }
  }
  (v = document.querySelector('[data-ms-form="signup"]')) == null || v.addEventListener("submit", async (s) => (s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation(), await i(s, "signup"), !1)), (d = document.querySelector('[data-ms-form="login"]')) == null || d.addEventListener("submit", async (s) => (s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation(), await i(s, "login"), !1)), document.querySelectorAll('[data-ms-auth-provider="google"]').forEach((s) => {
    s.addEventListener("click", async (r) => {
      r.preventDefault(), r.stopPropagation(), r.stopImmediatePropagation();
      const l = s.closest("[data-ms-form]");
      if (!l) {
        console.warn("No parent form with 'data-ms-form' found.");
        return;
      }
      l.getAttribute("data-ms-form") === "signup" ? await p(l, { provider: "google" }) : await c(l, { provider: "google" });
    });
  });
}
function C() {
  T(window.$memberstackDom);
  const n = new I(), e = "/default".split(",").map((t) => new RegExp(t)), o = (t) => e.some((a) => a.test(t));
  document.addEventListener(m.GET_APP, async () => {
    if (o(location.href)) {
      console.log("Avoided verification on excluded page");
      return;
    }
    if (console.log("getApp"), !S()) {
      P("unauthenticated");
      return;
    }
    try {
      if (await n.validateSessionStatus() === !1) {
        await window.$memberstackDom.logout();
        return;
      }
      P(!0);
    } catch (t) {
      if (t instanceof b) {
        (t.status === 401 || t.status === 403) && await window.$memberstackDom.logout({ isExpired: !0 });
        return;
      }
    }
  }, { once: !0 }), document.addEventListener(m.LOGOUT, async (t) => {
    const { detail: a } = t;
    if (console.log("logout"), !S()) {
      console.log("Member is not logged in.");
      return;
    }
    if (a != null && a.isExpired)
      await window.$memberstackDom._showMessage("Forbidden. Please login again.", !0);
    else
      try {
        await window.$memberstackDom._showMessage("Your session has expired. Please login again.", !0), await n.logout();
      } catch (i) {
        i instanceof b && (i.status === 401 || i.status === 403) && console.log("Member is already logged out from the server.");
      }
    await $(null, "/");
  }), document.addEventListener(m.LOGIN, async (t) => {
    console.log("login");
    const a = t.detail;
    if (!a && S()) {
      console.log("Member is already logged in."), await window.$memberstackDom._showMessage("Vous êtes déjà connecté.", !0);
      return;
    }
    try {
      if (function(c) {
        return "email" in c && "password" in c;
      }(a)) {
        const c = await n.login({ email: a.email, password: a.password });
        localStorage.setItem("_ms-mid", c.data.tokens.accessToken), localStorage.setItem("_ms-mem", JSON.stringify(c.data.member)), window.location.href = c.data.redirect;
      } else {
        const c = await n.loginWithProvider({ loginResponse: a });
        window.location.href = c.data.redirect;
      }
    } catch (i) {
      if (i instanceof E) {
        localStorage.removeItem("_ms-mid");
        const c = "_ms-2fa-session", p = JSON.stringify({ data: i.data, type: i.type });
        sessionStorage.setItem(c, p), k("/src/pages/2factor-challenge/");
        return;
      }
      throw i;
    }
  }), document.addEventListener(m.SIGN_UP, async (t) => {
    const a = t.detail;
    await n.signup({ token: a.data.tokens.accessToken });
  }), O();
}
C();
