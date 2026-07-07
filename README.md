# ordotype-auth-cdn

Build artifacts for Ordotype's authentication and monitoring scripts, served to browsers through [jsDelivr](https://www.jsdelivr.com/).

> **Do not edit the JavaScript files here by hand.** Everything in this repo except this README is generated. Each release of the source repository (`Ordotype/ordotype-authentication-proxy`) builds the bundles, replaces the files here via GitHub Actions (the `Deploy new build - Version X.Y.Z` commits), and creates a matching tag and GitHub Release. Hand edits would be overwritten by the next release and would break the version's SRI hashes.

## Files

| File | Purpose |
| --- | --- |
| `authentication.js` | Auth bootstrap for www.ordotype.fr: login/signup form binding (Memberstack), session handling, and the 2FA hand-off |
| `monitoring.js` | Error monitoring bootstrap (Sentry) |
| `vite.svg` | Build asset |

## How it is consumed

The Webflow site `<head>` pins an exact version with Subresource Integrity:

```
https://cdn.jsdelivr.net/gh/Ordotype/ordotype-auth-cdn@<version>/authentication.js
https://cdn.jsdelivr.net/gh/Ordotype/ordotype-auth-cdn@<version>/monitoring.js
```

Because the URLs are version-pinned, a release needs no cache purge: a new version is a new URL, which jsDelivr serves immediately. The scripts are loaded synchronously in the head (no `defer`/`async`); content gating depends on them running before the page body renders.

## Releasing

Releases are driven from the source repository's **Bump Version and Publish to CDN** workflow (manual `workflow_dispatch`). Publishing here is only half of a release: the version pinned in the Webflow head must then be bumped, along with **both** SRI hashes.

Compute SRI hashes from raw.githubusercontent.com, not from jsDelivr (jsDelivr can lag a fresh release by a minute or two and serve an error page or partial body, which yields a wrong hash and blocks the script site-wide):

```bash
curl -sL https://raw.githubusercontent.com/Ordotype/ordotype-auth-cdn/X.Y.Z/monitoring.js     | openssl dgst -sha384 -binary | openssl base64 -A
curl -sL https://raw.githubusercontent.com/Ordotype/ordotype-auth-cdn/X.Y.Z/authentication.js | openssl dgst -sha384 -binary | openssl base64 -A
```

The two hashes must differ (identical hashes mean you hashed an error page). Verify what jsDelivr actually serves:

```bash
curl -sI https://cdn.jsdelivr.net/gh/Ordotype/ordotype-auth-cdn@X.Y.Z/authentication.js | grep x-jsd-version
```
