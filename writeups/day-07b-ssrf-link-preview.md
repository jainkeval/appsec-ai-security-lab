# Day 7B - SSRF in Link Preview API

## Objective

Understand how a backend API can become vulnerable when it accepts a user-provided URL and makes the server fetch it.

The key lesson:

```txt
A URL starting with http:// or https:// is not automatically safe.
```

For SSRF, the dangerous question is:

```txt
Where is the backend server being forced to send a request?
```

## Vulnerable Pattern

The endpoint accepts a URL from the request body and directly makes a server-side HTTP request to it.

```js
import express from "express";
import axios from "axios";

const app = express();
app.use(express.json());

app.post("/api/link-preview", authMiddleware, async (req, res) => {
  try {
    const { url } = req.body;

    if (typeof url !== "string") {
      return res.status(400).json({ error: "url is required" });
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      return res.status(400).json({ error: "Invalid URL" });
    }

    const response = await axios.get(url, {
      timeout: 3000,
    });

    return res.json({
      url,
      status: response.status,
      preview: response.data.slice(0, 200),
    });
  } catch (err) {
    console.error("Preview failed:", err.message);
    return res.status(500).json({ error: "Could not generate preview" });
  }
});
```

The dangerous line is:

```js
const response = await axios.get(url, {
  timeout: 3000,
});
```

The issue is not that `axios` is unsafe.

The issue is that user-controlled input decides where the backend server sends a request.

## Why This Is Vulnerable

A normal user may send:

```http
POST /api/link-preview
Authorization: Bearer JWT_A
Content-Type: application/json

{
  "url": "https://example.com/blog/post-1"
}
```

But an attacker may send a URL that points to an internal or private target:

```http
POST /api/link-preview
Authorization: Bearer JWT_A
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```

The backend server, not the user's browser, makes the request.

That means the attacker may be able to make the server access resources that are not reachable from the public internet.

Examples of risky targets include:

```txt
http://localhost:3000/
http://127.0.0.1/
http://192.168.0.1/
http://10.0.0.5/
http://172.16.0.10/
http://169.254.169.254/
http://internal-service:8080/
```

This class of vulnerability is called:

```txt
SSRF - Server-Side Request Forgery
```

## Why Scheme Validation Is Not Enough

This validation is weak:

```js
if (!url.startsWith("http://") && !url.startsWith("https://")) {
  return res.status(400).json({ error: "Invalid URL" });
}
```

It only proves the URL uses HTTP or HTTPS.

It does not prove the destination is safe or public.

This URL still passes the check:

```txt
http://169.254.169.254/latest/meta-data/
```

But it may target internal cloud/server metadata.

Backend security rule:

```txt
Protocol validation is not destination validation.
```

## Impact

If exploited, SSRF can allow an attacker to:

- Reach internal services from the backend server.
- Access cloud metadata endpoints.
- Discover internal network services.
- Trigger actions on internal admin panels.
- Exfiltrate sensitive internal responses through the API.
- Bypass firewall assumptions because the request originates from a trusted server.

Authentication does not protect this endpoint.

Authentication proves who the user is.  
It does not make the user-provided URL safe.

## Regression Test

### Test Name

Link preview must not fetch cloud metadata or private internal URLs.

### Given

User A is authenticated.

User A can call:

```http
POST /api/link-preview
```

The API accepts a `url` field in the request body.

The backend must not fetch internal, private, loopback, link-local, or cloud metadata URLs.

### When

User A sends the following request:

```http
POST /api/link-preview
Authorization: Bearer JWT_A
Content-Type: application/json

{
  "url": "http://169.254.169.254/latest/meta-data/"
}
```

### Then

The API returns:

```http
400 Bad Request
```

The server must not make an outbound request to:

```txt
169.254.169.254
```

The response must not contain cloud metadata, secrets, internal service responses, or fetched content from the blocked URL.

Authentication must not cause the backend to trust the user-provided URL.

## Weak Defense: Blocklisting Known Bad URLs

This attempted fix is weak:

```js
if (
  url.includes("localhost") ||
  url.includes("127.0.0.1") ||
  url.includes("169.254.169.254")
) {
  return res.status(400).json({ error: "Blocked URL" });
}

const response = await axios.get(url);
```

This is not enough because the dangerous space is too large.

Attackers may try many other private/internal targets:

```txt
http://10.0.0.5/
http://172.16.0.10/
http://192.168.1.1/
http://[::1]/
http://internal-service:8080/
```

Blocklists are weak for SSRF because there are too many internal address formats, hostnames, encodings, DNS tricks, and redirect paths to reliably list.

A safer direction is:

```txt
Allow only approved public destinations.
```

## Weak Defense: url.includes()

This check is unsafe:

```js
const allowedHost = "trusted-news-site.com";

if (!url.includes(allowedHost)) {
  return res.status(400).json({ error: "URL host is not allowed" });
}
```

An attacker can send:

```txt
https://trusted-news-site.com.evil.com/article
```

This string contains:

```txt
trusted-news-site.com
```

But the real hostname is:

```txt
trusted-news-site.com.evil.com
```

That is not the trusted site.

The backend should parse the URL and check the real hostname:

```js
const parsedUrl = new URL(url);

if (!allowedHosts.has(parsedUrl.hostname)) {
  return res.status(400).json({ error: "URL host is not allowed" });
}
```

## Redirect Risk

Even if the first URL is trusted, redirects can still create SSRF risk.

Example:

```txt
https://trusted-news-site.com/redirect?to=http://169.254.169.254/latest/meta-data/
```

The first URL may look safe.

But if the backend automatically follows redirects, the final destination may be an internal/private URL.

Security rule:

```txt
A trusted first hop does not make the redirected second hop trusted.
```

For a strict link-preview API, one safer option is to disable automatic redirects:

```js
axios.get(url, {
  timeout: 3000,
  maxRedirects: 0,
});
```

This prevents the backend from automatically following a trusted-looking URL into an internal/private destination.

## Secure Fix

A safer implementation uses:

- Type validation.
- URL parsing with `new URL()`.
- `400 Bad Request` for malformed URLs.
- HTTPS-only URLs.
- Exact hostname allowlist.
- No automatic redirects.
- Timeout.
- No direct trust in user-provided URLs.

```js
import axios from "axios";

const allowedHosts = new Set([
  "example.com",
  "trusted-news-site.com",
]);

app.post("/api/link-preview", authMiddleware, async (req, res) => {
  try {
    const { url } = req.body;

    if (typeof url !== "string") {
      return res.status(400).json({ error: "URL required" });
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: "Invalid URL" });
    }

    if (parsedUrl.protocol !== "https:") {
      return res.status(400).json({ error: "Invalid URL" });
    }

    if (!allowedHosts.has(parsedUrl.hostname)) {
      return res.status(400).json({ error: "URL host is not allowed" });
    }

    const response = await axios.get(parsedUrl.toString(), {
      timeout: 3000,
      maxRedirects: 0,
    });

    return res.json({
      url: parsedUrl.toString(),
      status: response.status,
      preview: String(response.data).slice(0, 200),
    });
  } catch (err) {
    console.error("Preview failed:", err.message);
    return res.status(500).json({ error: "Could not generate preview" });
  }
});
```

## Why This Fix Is Safer

This check handles malformed URLs safely:

```js
try {
  parsedUrl = new URL(url);
} catch {
  return res.status(400).json({ error: "Invalid URL" });
}
```

This prevents invalid user input from becoming a `500 Internal Server Error`.

This check allows only HTTPS:

```js
if (parsedUrl.protocol !== "https:") {
  return res.status(400).json({ error: "Invalid URL" });
}
```

This checks the real parsed hostname, not a substring:

```js
if (!allowedHosts.has(parsedUrl.hostname)) {
  return res.status(400).json({ error: "URL host is not allowed" });
}
```

This prevents automatic redirect-following:

```js
maxRedirects: 0
```

This limits how long the backend waits:

```js
timeout: 3000
```

## Backend Security Rule

Never let a user-controlled URL freely decide where your backend server sends requests.

For SSRF-sensitive APIs:

- Do not rely only on `http://` or `https://` checks.
- Do not use simple string checks like `url.includes(...)`.
- Do not depend on blocklists as the main defense.
- Parse the URL with `new URL()`.
- Allow only approved public hosts when possible.
- Use exact hostname checks.
- Be careful with redirects.
- Use short timeouts.
- Treat authenticated users as still untrusted for input validation.
- Do not return internal service responses to users.

Authentication answers:

```txt
Who is the user?
```

URL validation answers:

```txt
Is the URL structurally valid?
```

Destination validation answers:

```txt
Is the backend allowed to connect to this host?
```

For SSRF prevention, destination validation is the critical check.
