var __defProp = Object.defineProperty;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
const MemberstackEvents = {
  LOGOUT: "memberstack.logout",
  GET_APP: "memberstack.getApp",
  LOGIN: "memberstack.login",
  VALID_SESSION: "memberstack.validSession",
  SIGN_UP: "memberstack.signUp"
};
function MemberstackInterceptor(memberstackInstance) {
  if (!memberstackInstance) {
    throw new Error("Memberstack instance is not defined");
  }
  if (!window._msConfig) {
    window._msConfig = {
      preventLogin: true
    };
  }
  window.$memberstackDom = new Proxy(memberstackInstance, {
    get(target, propKey) {
      const originalMethod = target[propKey];
      if (typeof originalMethod === "function") {
        return async function(...args) {
          console.log(
            `Method ${propKey} called with arguments: ${JSON.stringify(args)}`
          );
          if (propKey === "logout") {
            const evt = new CustomEvent(MemberstackEvents.LOGOUT, {
              bubbles: false,
              cancelable: false,
              detail: args[0]
            });
            document.dispatchEvent(evt);
            return false;
          }
          if (propKey === "getApp") {
            const evt = new Event(MemberstackEvents.GET_APP, {
              bubbles: false,
              cancelable: false
            });
            document.dispatchEvent(evt);
          }
          if (propKey === "loginMemberEmailPassword") {
            const evt = new CustomEvent(MemberstackEvents.LOGIN, {
              bubbles: false,
              cancelable: false,
              detail: args[0]
            });
            document.dispatchEvent(evt);
            return {
              data: {}
            };
          }
          if (propKey === "loginWithProvider") {
            const providerLogin = await originalMethod.apply(target, args);
            const evt = new CustomEvent(MemberstackEvents.LOGIN, {
              bubbles: false,
              cancelable: false,
              detail: providerLogin
            });
            document.dispatchEvent(evt);
            return providerLogin;
          }
          if (propKey === "signupWithProvider") {
            const signup = await originalMethod.apply(target, args);
            const evt = new CustomEvent(MemberstackEvents.SIGN_UP, {
              bubbles: false,
              cancelable: false,
              detail: signup
            });
            document.dispatchEvent(evt);
            return signup;
          }
          if (propKey === "signupMemberEmailPassword") {
            const signup = await originalMethod.apply(target, args);
            const evt = new CustomEvent(MemberstackEvents.SIGN_UP, {
              bubbles: false,
              cancelable: false,
              detail: signup
            });
            document.dispatchEvent(evt);
            return signup;
          }
          if (propKey === "getMemberCookie") {
            const cookie = await await originalMethod.apply(target, args);
            return String(cookie).toString();
          }
          return originalMethod.apply(target, args);
        };
      }
      return originalMethod;
    }
  });
}
function getDeviceId() {
  const cookieName = "_ga_7T2LX34911";
  const cookies = document.cookie.split("; ");
  for (const cookie of cookies) {
    const [name, value] = cookie.split("=");
    if (name === cookieName) {
      return value;
    }
  }
  throw new Error("Device Id cookie not found");
}
const BASE_URL = "https://api.ordotype.fr/v1.0.0";
class AuthError extends Error {
  constructor(message, status = 500) {
    super(message);
    __publicField(this, "status");
    this.name = "AuthError";
    this.status = status;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthError);
    }
  }
}
class TwoFactorRequiredError extends Error {
  constructor(message, data, type) {
    super(message);
    __publicField(this, "data");
    __publicField(this, "type");
    this.name = "TwoFactorRequiredError";
    this.data = data;
    this.type = type;
  }
}
class AuthService {
  constructor() {
    __publicField(this, "headers");
    const apiKey = "pk_97bbd1213f5b1bd2fc0f";
    const sessionId = window.localStorage.getItem("ms_session_id");
    const deviceId = getDeviceId();
    this.headers = {
      "X-Api-Key": apiKey,
      "X-Session-Id": sessionId ?? void 0,
      "X-Device-Id": deviceId ?? void 0
    };
  }
  async request(endpoint, entity, method = "GET", body = null, additionalHeaders = {}) {
    const url = `${BASE_URL}/${entity}/${endpoint}`;
    const headers = {
      "Content-Type": "application/json",
      ...this.headers,
      ...additionalHeaders
    };
    const options = {
      method,
      headers,
      ...body && { body: JSON.stringify(body) }
    };
    try {
      const response = await fetch(url, options);
      if (!response.ok) {
        throw new AuthError(response.statusText, response.status);
      }
      if (response.status === 204 || !response.body) {
        return null;
      }
      return await response.json();
    } catch (error) {
      console.error("API Request Failed:", error);
      throw error;
    }
  }
  async validateSessionStatus() {
    try {
      const memberToken = localStorage.getItem("_ms-mid");
      return await this.request(
        "validate-session-status",
        "auth",
        "POST",
        null,
        { Authorization: `Bearer ${memberToken}` }
      );
    } catch (error) {
      console.error("Session validation failed:", error);
      throw error;
    }
  }
  async logout() {
    try {
      const memberToken = localStorage.getItem("_ms-mid");
      await this.request(
        "logout",
        "auth",
        "POST",
        null,
        { Authorization: `Bearer ${memberToken}` }
      );
      localStorage.removeItem("_ms-mid");
    } catch (error) {
      console.error("Session logout failed:", error);
      throw error;
    }
  }
  async signup(params) {
    const payload = {
      ...params,
      device: this.headers["X-Device-Id"] ?? "unknown"
    };
    return await this.request(
      "signup",
      "auth",
      "POST",
      payload,
      {}
    );
  }
  async login(params) {
    const payload = {
      ...params,
      options: {
        includeContentGroups: true,
        isWebflow: true
      },
      device: this.headers["X-Device-Id"] ?? "unknown"
    };
    const res = await this.request(
      "login",
      "auth",
      "POST",
      payload,
      {}
    );
    if (isTwoFactorRequiredResponse(res)) {
      throw new TwoFactorRequiredError("2fa required", res.data, res.type);
    }
    return res;
  }
  async loginWithProvider(params) {
    const payload = {
      ...params,
      device: this.headers["X-Device-Id"] ?? "unknown"
    };
    const res = await this.request(
      "validate-google-provider",
      "auth",
      "POST",
      payload,
      {}
    );
    if (isTwoFactorRequiredResponse(res)) {
      throw new TwoFactorRequiredError("2fa required", res.data, res.type);
    }
    return res;
  }
  // Helper to get a cookie
  getCookie(name) {
    const matches = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
    return matches ? decodeURIComponent(matches[2]) : null;
  }
  // Helper to set a cookie with expiration time
  setCookie(name, value, expirationMs) {
    const date = /* @__PURE__ */ new Date();
    date.setTime(date.getTime() + expirationMs);
    document.cookie = `${name}=${encodeURIComponent(value)}; expires=${date.toUTCString()}; path=/`;
  }
  // Reusable throttle function
  async throttle(method, identifier, interval) {
    const lastExecution = this.getCookie(identifier);
    const now = Date.now();
    if (lastExecution && now - parseInt(lastExecution, 10) < interval) {
      console.log(`Skipping execution of ${identifier}: Throttled.`);
      return null;
    }
    console.log(`Executing ${identifier}...`);
    const result = await method();
    this.setCookie(identifier, now.toString(), interval);
    return result;
  }
  // Public wrapper for validateSessionStatus with throttling
  validateSessionStatusThrottled() {
    const memberToken = localStorage.getItem("_ms-mid");
    if (!memberToken) {
      return Promise.resolve(null);
    }
    return this.throttle(
      () => this.validateSessionStatus(),
      "lastSessionValidation",
      3 * 60 * 1e3
      // 3 minutes throttle interval
    );
  }
}
function isTwoFactorRequiredResponse(response) {
  return "data" in response && typeof response.data === "object" && "type" in response;
}
new AuthService();
function isMemberLoggedIn() {
  const memberToken = localStorage.getItem("_ms-mid");
  return !!memberToken;
}
function navigateTo(url) {
  window.$memberstackDom._showLoader();
  setTimeout(() => {
    window.location.href = url;
  }, 500);
}
const handleLogout = async (message, redirect = "/") => {
  localStorage.removeItem("_ms-mid");
  localStorage.removeItem("_ms-mem");
  navigateTo(redirect);
};
const dispatchValidationEvent = (isStatusValid) => {
  const validSessionEvt = new CustomEvent(MemberstackEvents.VALID_SESSION, {
    bubbles: false,
    cancelable: false,
    detail: { isStatusValid }
  });
  document.dispatchEvent(validSessionEvt);
};
function formUtils() {
  var _a, _b;
  function isProviderAuth(options) {
    return "provider" in options;
  }
  function isEmailPasswordAuth(options) {
    return "email" in options && "password" in options;
  }
  function getCustomFields(form) {
    const customFields = {};
    const inputs = form.querySelectorAll("[data-ms-member]");
    inputs.forEach((input) => {
      const memberKey = input.getAttribute("data-ms-member");
      if (memberKey && !["email", "password", "new-password", "current-password"].includes(memberKey)) {
        customFields[memberKey] = input.value || "";
      }
    });
    return customFields;
  }
  function getPlanAttributes(form) {
    const freePlan = form.getAttribute("data-ms-plan") || form.getAttribute("data-ms-plan:add") || form.getAttribute("data-ms-plan:update");
    const paidPlan = form.getAttribute("data-ms-price:add");
    return { freePlan, paidPlan };
  }
  async function handleError(message, error) {
    console.error(message, error);
    await window.$memberstackDom._showMessage((error == null ? void 0 : error.message) || "An error occurred", true);
  }
  async function formHandler(event, type) {
    var _a2, _b2;
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    const form = event.target;
    const email = (_a2 = form.querySelector('[data-ms-member="email"]')) == null ? void 0 : _a2.value;
    const password = (_b2 = form.querySelector('[data-ms-member="password"]')) == null ? void 0 : _b2.value;
    if (type === "signup") {
      await handleSignup(form, { email, password });
    } else if (type === "login") {
      await handleLogin(form, { email, password });
    }
  }
  async function handleLogin(_form, options) {
    let loginData;
    if (isProviderAuth(options)) {
      loginData = {
        provider: options.provider
      };
    } else if (isEmailPasswordAuth(options)) {
      loginData = {
        email: options.email,
        password: options.password
      };
    } else {
      throw new Error("Invalid form authentication options");
    }
    try {
      const hasLogin = isProviderAuth(options) ? await window.$memberstackDom.loginWithProvider(loginData) : await window.$memberstackDom.loginMemberEmailPassword(loginData);
      console.log("Signin successful:", hasLogin);
    } catch (error) {
      await handleError("Login failed:", error);
    }
  }
  async function handleSignup(form, options) {
    const customFields = getCustomFields(form);
    const { freePlan, paidPlan } = getPlanAttributes(form);
    let signupData = { customFields };
    if (isProviderAuth(options)) {
      signupData = {
        allowLogin: false,
        provider: options.provider
      };
    } else if (isEmailPasswordAuth(options)) {
      signupData = {
        email: options.email,
        password: options.password
      };
    } else {
      throw new Error("Invalid form authentication options");
    }
    if (freePlan) {
      signupData.plans = [{ planId: freePlan }];
    }
    try {
      window.$memberstackDom._showLoader();
      const hasSignup = isProviderAuth(options) ? await window.$memberstackDom.signupWithProvider(signupData) : await window.$memberstackDom.signupMemberEmailPassword(signupData);
      console.log("Signup successful:", hasSignup);
      if (paidPlan) {
        await window.$memberstackDom.purchasePlansWithCheckout({ priceId: paidPlan });
      } else {
        navigateTo(hasSignup.data.redirect);
      }
      window.$memberstackDom._hideLoader();
    } catch (error) {
      await handleError("Signup failed:", error);
      window.$memberstackDom._hideLoader();
    }
  }
  (_a = document.querySelector('[data-ms-form="signup"]')) == null ? void 0 : _a.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    await formHandler(event, "signup");
    return false;
  });
  (_b = document.querySelector('[data-ms-form="login"]')) == null ? void 0 : _b.addEventListener("submit", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    await formHandler(event, "login");
    return false;
  });
  document.querySelectorAll('[data-ms-auth-provider="google"]').forEach((element) => {
    element.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      const form = element.closest("[data-ms-form]");
      if (!form) {
        console.warn("No parent form with 'data-ms-form' found.");
        return;
      }
      if (form.getAttribute("data-ms-form") === "signup") {
        await handleSignup(form, { provider: "google" });
      } else {
        await handleLogin(form, { provider: "google" });
      }
    });
  });
  document.querySelectorAll('[data-ms-action="logout"]').forEach((element) => {
    element.addEventListener("click", async function(evt) {
      evt.preventDefault();
      evt.stopPropagation();
      evt.stopImmediatePropagation();
      await window.$memberstackDom.logout();
    });
  });
}
MemberstackInterceptor(window.$memberstackDom);
const authService = new AuthService();
const EXCLUDED_URL_PATTERNS = "/default".split(",").map((pattern) => new RegExp(pattern));
const isExcludedPage = (url) => {
  return EXCLUDED_URL_PATTERNS.some((pattern) => pattern.test(url));
};
document.addEventListener(MemberstackEvents.GET_APP, async () => {
  if (isExcludedPage(location.href)) {
    console.log("Avoided verification on excluded page");
    return;
  }
  console.log("getApp");
  if (!isMemberLoggedIn()) {
    dispatchValidationEvent("unauthenticated");
    return;
  }
  try {
    const isStatusValid = await authService.validateSessionStatus();
    if (isStatusValid === false) {
      await window.$memberstackDom.logout();
      return;
    }
    dispatchValidationEvent(true);
  } catch (error) {
    if (error instanceof AuthError) {
      if (error.status === 401 || error.status === 403) {
        await window.$memberstackDom.logout({ isExpired: true });
      }
      return;
    }
  }
}, { once: true });
document.addEventListener(MemberstackEvents.LOGOUT, async (ev) => {
  const { detail } = ev;
  console.log("logout");
  if (!isMemberLoggedIn()) {
    console.log("Member is not logged in.");
    return;
  }
  if (detail == null ? void 0 : detail.isExpired) {
    await window.$memberstackDom._showMessage("Votre session a expiré. Veuillez vous reconnecter.", true);
  } else {
    try {
      await authService.logout();
    } catch (error) {
      if (error instanceof AuthError) {
        if (error.status === 401 || error.status === 403) {
          console.log("Member is already logged out from the server.");
        }
      }
    }
  }
  await handleLogout(null, "/");
});
document.addEventListener(MemberstackEvents.LOGIN, async (event) => {
  console.log("login");
  const detail = event.detail;
  if (!detail && isMemberLoggedIn()) {
    console.log("Member is already logged in.");
    await window.$memberstackDom._showMessage("Vous êtes déjà connecté.", true);
    return;
  }
  try {
    let isEmailPasswordAuth = function(detail2) {
      return "email" in detail2 && "password" in detail2;
    };
    if (isEmailPasswordAuth(detail)) {
      const res = await authService.login({ email: detail.email, password: detail.password });
      localStorage.setItem("_ms-mid", res.data.tokens.accessToken);
      localStorage.setItem("_ms-mem", JSON.stringify(res.data.member));
      window.location.href = res.data.redirect;
    } else {
      const res = await authService.loginWithProvider({ loginResponse: detail });
      window.location.href = res.data.redirect;
    }
  } catch (error) {
    if (error instanceof TwoFactorRequiredError) {
      localStorage.removeItem("_ms-mid");
      const SESSION_NAME = "_ms-2fa-session";
      const session = JSON.stringify({ data: error.data, type: error.type });
      sessionStorage.setItem(SESSION_NAME, session);
      navigateTo("/membership/connexion-2fa");
      return;
    }
    throw error;
  }
});
document.addEventListener(MemberstackEvents.SIGN_UP, async (event) => {
  const memberData = event.detail;
  await authService.signup({ token: memberData.data.tokens.accessToken });
});
formUtils();
