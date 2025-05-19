var D = Object.defineProperty;
var T = (a, e, t) => e in a ? D(a, e, { enumerable: !0, configurable: !0, writable: !0, value: t }) : a[e] = t;
var p = (a, e, t) => T(a, typeof e != "symbol" ? e + "" : e, t);
const m = {
  LOGOUT: "memberstack.logout",
  GET_APP: "memberstack.getApp",
  LOGIN: "memberstack.login",
  VALID_SESSION: "memberstack.validSession",
  SIGN_UP: "memberstack.signUp"
};
function A(a) {
  if (!a)
    throw new Error("Memberstack instance is not defined");
  window._msConfig || (window._msConfig = {
    preventLogin: !0
  }), window.$memberstackDom = new Proxy(a, {
    get(e, t) {
      const o = e[t];
      return typeof o == "function" ? async function(...i) {
        if (console.log(
          `Method ${t} called with arguments: ${JSON.stringify(i)}`
        ), t === "logout") {
          const r = new CustomEvent(m.LOGOUT, {
            bubbles: !1,
            cancelable: !1,
            detail: i[0]
          });
          return document.dispatchEvent(r), !1;
        }
        if (t === "getApp") {
          const r = new Event(m.GET_APP, {
            bubbles: !1,
            cancelable: !1
          });
          document.dispatchEvent(r);
        }
        if (t === "loginMemberEmailPassword") {
          const r = new CustomEvent(m.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: i[0]
          });
          return document.dispatchEvent(r), {
            data: {}
          };
        }
        if (t === "loginWithProvider") {
          const r = await o.apply(e, i), l = new CustomEvent(m.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: r
          });
          return document.dispatchEvent(l), r;
        }
        if (t === "signupWithProvider") {
          const r = await o.apply(e, i), l = new CustomEvent(m.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: r
          });
          return document.dispatchEvent(l), r;
        }
        if (t === "signupMemberEmailPassword") {
          const r = await o.apply(e, i), l = new CustomEvent(m.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: r
          });
          return document.dispatchEvent(l), r;
        }
        return o.apply(e, i);
      } : o;
    }
  });
}
function L() {
  const a = "_ga_7T2LX34911", e = document.cookie.split("; ");
  for (const t of e) {
    const [o, i] = t.split("=");
    if (o === a)
      return i;
  }
  throw new Error("Device Id cookie not found");
}
const $ = "https://staging-api.ordotype.fr/v1.0.0";
class b extends Error {
  constructor(t, o = 500) {
    super(t);
    p(this, "status");
    this.name = "AuthError", this.status = o, Error.captureStackTrace && Error.captureStackTrace(this, b);
  }
}
class E extends Error {
  constructor(t, o, i) {
    super(t);
    p(this, "data");
    p(this, "type");
    this.name = "TwoFactorRequiredError", this.data = o, this.type = i;
  }
}
class _ {
  constructor() {
    p(this, "headers");
    const e = "pk_sb_e80d8429a51c2ceb0530", t = window.localStorage.getItem("ms_session_id"), o = L();
    this.headers = {
      "X-Api-Key": e,
      "X-Session-Id": t ?? void 0,
      "X-Device-Id": o ?? void 0
    };
  }
  async request(e, t, o = "GET", i = null, r = {}) {
    const l = `${$}/${t}/${e}`, v = {
      "Content-Type": "application/json",
      ...this.headers,
      ...r
    }, S = {
      method: o,
      headers: v,
      ...i && { body: JSON.stringify(i) }
    };
    try {
      const d = await fetch(l, S);
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
    const t = {
      ...e,
      device: this.headers["X-Device-Id"] ?? "unknown"
    };
    return await this.request(
      "signup",
      "auth",
      "POST",
      t,
      {}
    );
  }
  async login(e) {
    const t = {
      ...e,
      options: {
        includeContentGroups: !0,
        isWebflow: !0
      },
      device: this.headers["X-Device-Id"] ?? "unknown"
    }, o = await this.request(
      "login",
      "auth",
      "POST",
      t,
      {}
    );
    if (P(o))
      throw new E("2fa required", o.data, o.type);
    return o;
  }
  async loginWithProvider(e) {
    const t = {
      ...e,
      device: this.headers["X-Device-Id"] ?? "unknown"
    }, o = await this.request(
      "validate-google-provider",
      "auth",
      "POST",
      t,
      {}
    );
    if (P(o))
      throw new E("2fa required", o.data, o.type);
    return o;
  }
  // Helper to get a cookie
  getCookie(e) {
    const t = document.cookie.match(new RegExp(`(^| )${e}=([^;]+)`));
    return t ? decodeURIComponent(t[2]) : null;
  }
  // Helper to set a cookie with expiration time
  setCookie(e, t, o) {
    const i = /* @__PURE__ */ new Date();
    i.setTime(i.getTime() + o), document.cookie = `${e}=${encodeURIComponent(t)}; expires=${i.toUTCString()}; path=/`;
  }
  // Reusable throttle function
  async throttle(e, t, o) {
    const i = this.getCookie(t), r = Date.now();
    if (i && r - parseInt(i, 10) < o)
      return console.log(`Skipping execution of ${t}: Throttled.`), null;
    console.log(`Executing ${t}...`);
    const l = await e();
    return this.setCookie(t, r.toString(), o), l;
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
function P(a) {
  return "data" in a && typeof a.data == "object" && "type" in a;
}
new _();
function k() {
  return !!localStorage.getItem("_ms-mid");
}
function y(a) {
  window.$memberstackDom._showLoader(), setTimeout(() => {
    window.location.href = a;
  }, 500);
}
const O = async (a, e = "/") => {
  await window.$memberstackDom.logout(), localStorage.removeItem("_ms-mid"), localStorage.removeItem("_ms_mem"), y(e);
}, I = (a) => {
  const e = new CustomEvent(m.VALID_SESSION, {
    bubbles: !1,
    cancelable: !1,
    detail: { isStatusValid: a }
  });
  document.dispatchEvent(e);
};
function C() {
  var S, d;
  function a(s) {
    return "provider" in s;
  }
  function e(s) {
    return "email" in s && "password" in s;
  }
  function t(s) {
    const n = {};
    return s.querySelectorAll("[data-ms-member]").forEach((u) => {
      const w = u.getAttribute("data-ms-member");
      w && !["email", "password", "new-password", "current-password"].includes(w) && (n[w] = u.value || "");
    }), n;
  }
  function o(s) {
    const n = s.getAttribute("data-ms-plan") || s.getAttribute("data-ms-plan:add") || s.getAttribute("data-ms-plan:update"), c = s.getAttribute("data-ms-price:add");
    return { freePlan: n, paidPlan: c };
  }
  async function i(s, n) {
    console.error(s, n), await window.$memberstackDom._showMessage((n == null ? void 0 : n.message) || "An error occurred", !0);
  }
  async function r(s, n) {
    var g, f;
    s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation();
    const c = s.target, u = (g = c.querySelector('[data-ms-member="email"]')) == null ? void 0 : g.value, w = (f = c.querySelector('[data-ms-member="password"]')) == null ? void 0 : f.value;
    n === "signup" ? await v(c, { email: u, password: w }) : n === "login" && await l(c, { email: u, password: w });
  }
  async function l(s, n) {
    let c;
    if (a(n))
      c = {
        provider: n.provider
      };
    else if (e(n))
      c = {
        email: n.email,
        password: n.password
      };
    else
      throw new Error("Invalid form authentication options");
    try {
      const u = a(n) ? await window.$memberstackDom.loginWithProvider(c) : await window.$memberstackDom.loginMemberEmailPassword(c);
      console.log("Signin successful:", u);
    } catch (u) {
      await i("Login failed:", u);
    }
  }
  async function v(s, n) {
    const c = t(s), { freePlan: u, paidPlan: w } = o(s);
    let g = { customFields: c };
    if (a(n))
      g = {
        allowLogin: !1,
        provider: n.provider
      };
    else if (e(n))
      g = {
        email: n.email,
        password: n.password
      };
    else
      throw new Error("Invalid form authentication options");
    u && (g.plans = [{ planId: u }]);
    try {
      window.$memberstackDom._showLoader();
      const f = a(n) ? await window.$memberstackDom.signupWithProvider(g) : await window.$memberstackDom.signupMemberEmailPassword(g);
      console.log("Signup successful:", f), w ? await window.$memberstackDom.purchasePlansWithCheckout({ priceId: w }) : y(f.data.redirect), window.$memberstackDom._hideLoader();
    } catch (f) {
      await i("Signup failed:", f), window.$memberstackDom._hideLoader();
    }
  }
  (S = document.querySelector('[data-ms-form="signup"]')) == null || S.addEventListener("submit", async (s) => (s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation(), await r(s, "signup"), !1)), (d = document.querySelector('[data-ms-form="login"]')) == null || d.addEventListener("submit", async (s) => (s.preventDefault(), s.stopPropagation(), s.stopImmediatePropagation(), await r(s, "login"), !1)), document.querySelectorAll('[data-ms-auth-provider="google"]').forEach((s) => {
    s.addEventListener("click", async (n) => {
      n.preventDefault(), n.stopPropagation(), n.stopImmediatePropagation();
      const c = s.closest("[data-ms-form]");
      if (!c) {
        console.warn("No parent form with 'data-ms-form' found.");
        return;
      }
      c.getAttribute("data-ms-form") === "signup" ? await v(c, { provider: "google" }) : await l(c, { provider: "google" });
    });
  });
}
A(window.$memberstackDom);
const h = new _(), N = "/default".split(",").map((a) => new RegExp(a)), q = (a) => N.some((e) => e.test(a));
document.addEventListener(m.GET_APP, async () => {
  if (q(location.href)) {
    console.log("Avoided verification on excluded page");
    return;
  }
  if (console.log("getApp"), !k()) {
    I("unauthenticated");
    return;
  }
  try {
    if (await h.validateSessionStatus() === !1) {
      await window.$memberstackDom.logout();
      return;
    }
    I(!0);
  } catch (a) {
    if (a instanceof b) {
      (a.status === 401 || a.status === 403) && await window.$memberstackDom.logout({ isExpired: !0 });
      return;
    }
  }
}, { once: !0 });
document.addEventListener(m.LOGOUT, async (a) => {
  const { detail: e } = a;
  if (console.log("logout"), !k()) {
    console.log("Member is not logged in.");
    return;
  }
  if (e != null && e.isExpired)
    await window.$memberstackDom._showMessage("Forbidden. Please login again.", !0);
  else
    try {
      await window.$memberstackDom._showMessage("Your session has expired. Please login again.", !0), await h.logout();
    } catch (t) {
      t instanceof b && (t.status === 401 || t.status === 403) && console.log("Member is already logged out from the server.");
    }
  await O(null, "/");
});
document.addEventListener(m.LOGIN, async (a) => {
  console.log("login");
  const e = a.detail;
  if (!e && k()) {
    console.log("Member is already logged in."), await window.$memberstackDom._showMessage("Vous êtes déjà connecté.", !0);
    return;
  }
  try {
    if (function(o) {
      return "email" in o && "password" in o;
    }(e)) {
      const o = await h.login({ email: e.email, password: e.password });
      localStorage.setItem("_ms-mid", o.data.tokens.accessToken), localStorage.setItem("_ms-mem", JSON.stringify(o.data.member)), window.location.href = o.data.redirect;
    } else {
      const o = await h.loginWithProvider({ loginResponse: e });
      window.location.href = o.data.redirect;
    }
  } catch (t) {
    if (t instanceof E) {
      localStorage.removeItem("_ms-mid");
      const o = "_ms-2fa-session", i = JSON.stringify({ data: t.data, type: t.type });
      sessionStorage.setItem(o, i), y("/src/pages/2factor-challenge/");
      return;
    }
    throw t;
  }
});
document.addEventListener(m.SIGN_UP, async (a) => {
  const e = a.detail;
  await h.signup({ token: e.data.tokens.accessToken });
});
C();
