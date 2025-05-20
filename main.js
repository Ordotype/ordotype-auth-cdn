var _ = Object.defineProperty;
var D = (r, e, t) => e in r ? _(r, e, { enumerable: !0, configurable: !0, writable: !0, value: t }) : r[e] = t;
var b = (r, e, t) => D(r, typeof e != "symbol" ? e + "" : e, t);
const w = {
  LOGOUT: "memberstack.logout",
  GET_APP: "memberstack.getApp",
  LOGIN: "memberstack.login",
  VALID_SESSION: "memberstack.validSession",
  SIGN_UP: "memberstack.signUp"
};
function T(r) {
  if (!r)
    throw new Error("Memberstack instance is not defined");
  window._msConfig || (window._msConfig = {
    preventLogin: !0
  }), window.$memberstackDom = new Proxy(r, {
    get(e, t) {
      const s = e[t];
      return typeof s == "function" ? async function(...o) {
        if (console.log(
          `Method ${t} called with arguments: ${JSON.stringify(o)}`
        ), t === "logout") {
          const a = new CustomEvent(w.LOGOUT, {
            bubbles: !1,
            cancelable: !1,
            detail: o[0]
          });
          return document.dispatchEvent(a), !1;
        }
        if (t === "getApp") {
          const a = new Event(w.GET_APP, {
            bubbles: !1,
            cancelable: !1
          });
          document.dispatchEvent(a);
        }
        if (t === "loginMemberEmailPassword") {
          const a = new CustomEvent(w.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: o[0]
          });
          return document.dispatchEvent(a), {
            data: {}
          };
        }
        if (t === "loginWithProvider") {
          const a = await s.apply(e, o), c = new CustomEvent(w.LOGIN, {
            bubbles: !1,
            cancelable: !1,
            detail: a
          });
          return document.dispatchEvent(c), a;
        }
        if (t === "signupWithProvider") {
          const a = await s.apply(e, o), c = new CustomEvent(w.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: a
          });
          return document.dispatchEvent(c), a;
        }
        if (t === "signupMemberEmailPassword") {
          const a = await s.apply(e, o), c = new CustomEvent(w.SIGN_UP, {
            bubbles: !1,
            cancelable: !1,
            detail: a
          });
          return document.dispatchEvent(c), a;
        }
        return s.apply(e, o);
      } : s;
    }
  });
}
function A() {
  const r = "_ga_7T2LX34911", e = document.cookie.split("; ");
  for (const t of e) {
    const [s, o] = t.split("=");
    if (s === r)
      return o;
  }
  throw new Error("Device Id cookie not found");
}
const L = "https://staging-api.ordotype.fr/v1.0.0";
class v extends Error {
  constructor(t, s = 500) {
    super(t);
    b(this, "status");
    this.name = "AuthError", this.status = s, Error.captureStackTrace && Error.captureStackTrace(this, v);
  }
}
class E extends Error {
  constructor(t, s, o) {
    super(t);
    b(this, "data");
    b(this, "type");
    this.name = "TwoFactorRequiredError", this.data = s, this.type = o;
  }
}
class I {
  constructor() {
    b(this, "headers");
    const e = "pk_sb_e80d8429a51c2ceb0530", t = window.localStorage.getItem("ms_session_id"), s = A();
    this.headers = {
      "X-Api-Key": e,
      "X-Session-Id": t ?? void 0,
      "X-Device-Id": s ?? void 0
    };
  }
  async request(e, t, s = "GET", o = null, a = {}) {
    const c = `${L}/${t}/${e}`, d = {
      "Content-Type": "application/json",
      ...this.headers,
      ...a
    }, h = {
      method: s,
      headers: d,
      ...o && { body: JSON.stringify(o) }
    };
    try {
      const u = await fetch(c, h);
      if (!u.ok)
        throw new v(u.statusText, u.status);
      return u.status === 204 || !u.body ? null : await u.json();
    } catch (u) {
      throw console.error("API Request Failed:", u), u;
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
    }, s = await this.request(
      "login",
      "auth",
      "POST",
      t,
      {}
    );
    if (y(s))
      throw new E("2fa required", s.data, s.type);
    return s;
  }
  async loginWithProvider(e) {
    const t = {
      ...e,
      device: this.headers["X-Device-Id"] ?? "unknown"
    }, s = await this.request(
      "validate-google-provider",
      "auth",
      "POST",
      t,
      {}
    );
    if (y(s))
      throw new E("2fa required", s.data, s.type);
    return s;
  }
  // Helper to get a cookie
  getCookie(e) {
    const t = document.cookie.match(new RegExp(`(^| )${e}=([^;]+)`));
    return t ? decodeURIComponent(t[2]) : null;
  }
  // Helper to set a cookie with expiration time
  setCookie(e, t, s) {
    const o = /* @__PURE__ */ new Date();
    o.setTime(o.getTime() + s), document.cookie = `${e}=${encodeURIComponent(t)}; expires=${o.toUTCString()}; path=/`;
  }
  // Reusable throttle function
  async throttle(e, t, s) {
    const o = this.getCookie(t), a = Date.now();
    if (o && a - parseInt(o, 10) < s)
      return console.log(`Skipping execution of ${t}: Throttled.`), null;
    console.log(`Executing ${t}...`);
    const c = await e();
    return this.setCookie(t, a.toString(), s), c;
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
function y(r) {
  return "data" in r && typeof r.data == "object" && "type" in r;
}
new I();
function S() {
  return !!localStorage.getItem("_ms-mid");
}
function k(r) {
  window.$memberstackDom._showLoader(), setTimeout(() => {
    window.location.href = r;
  }, 500);
}
const $ = async (r, e = "/") => {
  await window.$memberstackDom.logout(), localStorage.removeItem("_ms-mid"), localStorage.removeItem("_ms_mem"), k(e);
}, P = (r) => {
  const e = new CustomEvent(w.VALID_SESSION, {
    bubbles: !1,
    cancelable: !1,
    detail: { isStatusValid: r }
  });
  document.dispatchEvent(e);
};
function O() {
  var h, u;
  function r(n) {
    return "provider" in n;
  }
  function e(n) {
    return "email" in n && "password" in n;
  }
  function t(n) {
    const i = {};
    return n.querySelectorAll("[data-ms-member]").forEach((m) => {
      const g = m.getAttribute("data-ms-member");
      g && !["email", "password", "new-password", "current-password"].includes(g) && (i[g] = m.value || "");
    }), i;
  }
  function s(n) {
    const i = n.getAttribute("data-ms-plan") || n.getAttribute("data-ms-plan:add") || n.getAttribute("data-ms-plan:update"), l = n.getAttribute("data-ms-price:add");
    return { freePlan: i, paidPlan: l };
  }
  async function o(n, i) {
    console.error(n, i), await window.$memberstackDom._showMessage((i == null ? void 0 : i.message) || "An error occurred", !0);
  }
  async function a(n, i) {
    var f, p;
    n.preventDefault(), n.stopPropagation(), n.stopImmediatePropagation();
    const l = n.target, m = (f = l.querySelector('[data-ms-member="email"]')) == null ? void 0 : f.value, g = (p = l.querySelector('[data-ms-member="password"]')) == null ? void 0 : p.value;
    i === "signup" ? await d(l, { email: m, password: g }) : i === "login" && await c(l, { email: m, password: g });
  }
  async function c(n, i) {
    let l;
    if (r(i))
      l = {
        provider: i.provider
      };
    else if (e(i))
      l = {
        email: i.email,
        password: i.password
      };
    else
      throw new Error("Invalid form authentication options");
    try {
      const m = r(i) ? await window.$memberstackDom.loginWithProvider(l) : await window.$memberstackDom.loginMemberEmailPassword(l);
      console.log("Signin successful:", m);
    } catch (m) {
      await o("Login failed:", m);
    }
  }
  async function d(n, i) {
    const l = t(n), { freePlan: m, paidPlan: g } = s(n);
    let f = { customFields: l };
    if (r(i))
      f = {
        allowLogin: !1,
        provider: i.provider
      };
    else if (e(i))
      f = {
        email: i.email,
        password: i.password
      };
    else
      throw new Error("Invalid form authentication options");
    m && (f.plans = [{ planId: m }]);
    try {
      window.$memberstackDom._showLoader();
      const p = r(i) ? await window.$memberstackDom.signupWithProvider(f) : await window.$memberstackDom.signupMemberEmailPassword(f);
      console.log("Signup successful:", p), g ? await window.$memberstackDom.purchasePlansWithCheckout({ priceId: g }) : k(p.data.redirect), window.$memberstackDom._hideLoader();
    } catch (p) {
      await o("Signup failed:", p), window.$memberstackDom._hideLoader();
    }
  }
  (h = document.querySelector('[data-ms-form="signup"]')) == null || h.addEventListener("submit", async (n) => (n.preventDefault(), n.stopPropagation(), n.stopImmediatePropagation(), await a(n, "signup"), !1)), (u = document.querySelector('[data-ms-form="login"]')) == null || u.addEventListener("submit", async (n) => (n.preventDefault(), n.stopPropagation(), n.stopImmediatePropagation(), await a(n, "login"), !1)), document.querySelectorAll('[data-ms-auth-provider="google"]').forEach((n) => {
    n.addEventListener("click", async (i) => {
      i.preventDefault(), i.stopPropagation(), i.stopImmediatePropagation();
      const l = n.closest("[data-ms-form]");
      if (!l) {
        console.warn("No parent form with 'data-ms-form' found.");
        return;
      }
      l.getAttribute("data-ms-form") === "signup" ? await d(l, { provider: "google" }) : await c(l, { provider: "google" });
    });
  });
}
(function() {
  T(window.$memberstackDom);
  const e = new I(), t = "/default".split(",").map((o) => new RegExp(o)), s = (o) => t.some((a) => a.test(o));
  document.addEventListener(w.GET_APP, async () => {
    if (s(location.href)) {
      console.log("Avoided verification on excluded page");
      return;
    }
    if (console.log("getApp"), !S()) {
      P("unauthenticated");
      return;
    }
    try {
      if (await e.validateSessionStatus() === !1) {
        await window.$memberstackDom.logout();
        return;
      }
      P(!0);
    } catch (o) {
      if (o instanceof v) {
        (o.status === 401 || o.status === 403) && await window.$memberstackDom.logout({ isExpired: !0 });
        return;
      }
    }
  }, { once: !0 }), document.addEventListener(w.LOGOUT, async (o) => {
    const { detail: a } = o;
    if (console.log("logout"), !S()) {
      console.log("Member is not logged in.");
      return;
    }
    if (a != null && a.isExpired)
      await window.$memberstackDom._showMessage("Forbidden. Please login again.", !0);
    else
      try {
        await window.$memberstackDom._showMessage("Your session has expired. Please login again.", !0), await e.logout();
      } catch (c) {
        c instanceof v && (c.status === 401 || c.status === 403) && console.log("Member is already logged out from the server.");
      }
    await $(null, "/");
  }), document.addEventListener(w.LOGIN, async (o) => {
    console.log("login");
    const a = o.detail;
    if (!a && S()) {
      console.log("Member is already logged in."), await window.$memberstackDom._showMessage("Vous êtes déjà connecté.", !0);
      return;
    }
    try {
      if (function(d) {
        return "email" in d && "password" in d;
      }(a)) {
        const d = await e.login({ email: a.email, password: a.password });
        localStorage.setItem("_ms-mid", d.data.tokens.accessToken), localStorage.setItem("_ms-mem", JSON.stringify(d.data.member)), window.location.href = d.data.redirect;
      } else {
        const d = await e.loginWithProvider({ loginResponse: a });
        window.location.href = d.data.redirect;
      }
    } catch (c) {
      if (c instanceof E) {
        localStorage.removeItem("_ms-mid");
        const d = "_ms-2fa-session", h = JSON.stringify({ data: c.data, type: c.type });
        sessionStorage.setItem(d, h), k("/src/pages/2factor-challenge/");
        return;
      }
      throw c;
    }
  }), document.addEventListener(w.SIGN_UP, async (o) => {
    const a = o.detail;
    await e.signup({ token: a.data.tokens.accessToken });
  }), O();
})();
