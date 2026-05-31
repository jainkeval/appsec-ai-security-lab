# Day 8 - Login User Enumeration and Rate Limiting

## Objective

Understand how a login endpoint can check passwords correctly but still leak useful information to attackers.

Key lesson:

```txt
Safe authentication is not only about checking the password.
It is also about avoiding attacker-visible differences in failure behavior.
```

## Vulnerable Pattern

```js
import express from "express";
import bcrypt from "bcrypt";

const app = express();
app.use(express.json());

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = await db.users.findUnique({
    where: { email },
  });

  if (!user) {
    return res.status(401).json({ error: "User does not exist" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Password is incorrect" });
  }

  return res.json({
    token: signJwt({ userId: user.id, role: user.role }),
  });
});
```

The dangerous behavior is returning different errors:

```js
return res.status(401).json({ error: "User does not exist" });
```

versus:

```js
return res.status(401).json({ error: "Password is incorrect" });
```

This lets an attacker test emails one by one and learn which accounts exist.

## Why This Is Vulnerable

An attacker sends:

```http
POST /api/login
Content-Type: application/json

{
  "email": "keval@example.com",
  "password": "wrong-password"
}
```

If the response says:

```json
{
  "error": "Password is incorrect"
}
```

the attacker learns:

```txt
keval@example.com is probably a valid account.
```

Then the attacker sends:

```http
POST /api/login
Content-Type: application/json

{
  "email": "random-user-123@example.com",
  "password": "wrong-password"
}
```

If the response says:

```json
{
  "error": "User does not exist"
}
```

the attacker learns:

```txt
random-user-123@example.com is probably not a valid account.
```

This is called:

```txt
User enumeration
```

The attacker does not need the password yet. They can first build a list of valid users and later use that list for phishing, brute force, credential stuffing, or social engineering.

## Regression Test 1

### Test Name

Login must not reveal whether an email exists.

### Given

`keval@example.com` is a valid user.

The password for `keval@example.com` is not:

```txt
wrong-password
```

`random-user-123@example.com` is not a valid user.

The login endpoint must not reveal whether an email exists.

### When

A login attempt is made with a real email and a wrong password:

```http
POST /api/login
Content-Type: application/json

{
  "email": "keval@example.com",
  "password": "wrong-password"
}
```

### Then

The API returns:

```http
401 Unauthorized
```

The response body is generic:

```json
{
  "error": "Email or password is incorrect"
}
```

### When

A login attempt is made with a non-existing email and a wrong password:

```http
POST /api/login
Content-Type: application/json

{
  "email": "random-user-123@example.com",
  "password": "wrong-password"
}
```

### Then

The API returns:

```http
401 Unauthorized
```

The response body is the same generic response:

```json
{
  "error": "Email or password is incorrect"
}
```

Both responses must be indistinguishable from the attacker's perspective.

## Timing Side Channel

Changing only the error message is not enough.

This attempted fix still has a weakness:

```js
const user = await db.users.findUnique({
  where: { email },
});

if (!user) {
  return res.status(401).json({ error: "Email or password is incorrect" });
}

const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

if (!isPasswordValid) {
  return res.status(401).json({ error: "Email or password is incorrect" });
}
```

The message is generic, but the timing may still differ.

For a missing user:

```txt
DB lookup -> return 401 quickly
```

For a real user with the wrong password:

```txt
DB lookup -> bcrypt.compare(...) -> return 401 slower
```

`bcrypt.compare()` is intentionally expensive.

An attacker may measure response times and infer:

```txt
slower response = email probably exists
faster response = email probably does not exist
```

This is a timing side channel.

## Safer Login Failure Logic

To reduce the obvious timing gap, the missing-user path should also perform a bcrypt comparison using a dummy bcrypt hash.

Important:

```txt
The dummy hash must be a real bcrypt hash with the same cost factor as real password hashes.
```

```js
const DUMMY_PASSWORD_HASH =
  "$2b$10$abcdefghijklmnopqrstuuV6Q1NQx7NQx7NQx7NQx7NQx7NQx7NQx";

const user = await db.users.findUnique({
  where: { email },
});

const passwordHashToCompare = user
  ? user.passwordHash
  : DUMMY_PASSWORD_HASH;

const validPassword = await bcrypt.compare(password, passwordHashToCompare);

if (!user || !validPassword) {
  return res.status(401).json({
    error: "Email or password is incorrect",
  });
}

return res.json({
  token: signJwt({ userId: user.id, role: user.role }),
});
```

This does not make timing perfectly identical, but it reduces the obvious gap between missing-user and wrong-password paths.

## Brute Force and Credential Stuffing Risk

Even with generic messages and dummy bcrypt comparison, attackers can still automate many login attempts.

This creates risk of:

```txt
brute force
credential stuffing
CPU exhaustion
login endpoint DoS
```

The login endpoint should use rate limiting / throttling.

Useful rate-limit dimensions include:

```txt
IP
email/account
IP + email
device/session fingerprint when available
```

Do not rely on only one dimension.

Email-only rate limiting is weak because an attacker can intentionally trigger failed attempts for a victim email and cause denial of service.

IP-only rate limiting is weak because attackers can rotate IPs, and many real users may share one IP behind NAT or mobile networks.

Device information can help, but headers like `User-Agent` can be spoofed.

## Rate Limit Response

When the request pattern is being throttled, the API should return:

```http
429 Too Many Requests
```

Safe response body:

```json
{
  "error": "Too many login attempts. Please try again later."
}
```

Optional header:

```http
Retry-After: 300
```

Avoid responses like:

```txt
Account blocked
Account locked
This email is under attack
```

Those responses may reveal account state or support denial-of-service attacks.

Security rule:

```txt
401 = credentials failed
429 = too many attempts
Do not reveal account existence or lockout state
```

## Rate Limit Placement

Rate-limit enforcement should happen before expensive bcrypt work.

Why:

```txt
bcrypt is intentionally CPU-expensive.
```

If an attacker sends thousands of login attempts and the backend always runs bcrypt first, the attacker can consume server CPU.

Correct flow:

```txt
1. Validate input shape.
2. Enforce rate limit before bcrypt.
3. Lookup user.
4. Always run bcrypt compare using a real or dummy hash.
5. If login failed, record the failed attempt and return generic 401.
6. If login succeeded, reset relevant counters and issue the token.
```

This means:

```txt
Enforce before bcrypt.
Update failure counters after bcrypt.
```

## Regression Test 2

### Test Name

Login should throttle repeated failed attempts.

### Given

User A is making login requests from the same IP address.

The login endpoint accepts:

```http
POST /api/login
```

The rate limiter tracks failed login attempts using multiple dimensions, such as:

```txt
IP
email
IP + email
```

The configured threshold allows only a limited number of failed attempts within a fixed time window.

The API must not reveal whether the submitted email exists.

### When

User A repeatedly sends wrong passwords for the same email from the same IP address:

```http
POST /api/login
Content-Type: application/json

{
  "email": "keval@example.com",
  "password": "wrong-password"
}
```

After the allowed failure threshold is reached, User A sends another login request:

```http
POST /api/login
Content-Type: application/json

{
  "email": "keval@example.com",
  "password": "another-wrong-password"
}
```

### Then

The API returns:

```http
429 Too Many Requests
```

The response body is generic:

```json
{
  "error": "Too many login attempts. Please try again later."
}
```

The response must not reveal whether:

```txt
keval@example.com exists
the account is locked
the password was wrong
the account is under attack
```

The blocked request must not run expensive password verification work such as:

```js
bcrypt.compare(...)
```

The backend should reject the request at the rate-limit enforcement step before doing CPU-expensive authentication work.

## Secure Fix

This example combines:

```txt
generic login errors
dummy bcrypt hash for missing users
rate-limit enforcement before bcrypt
recording failed attempts after failed authentication
resetting counters after successful authentication
```

```js
import bcrypt from "bcrypt";

const DUMMY_PASSWORD_HASH =
  "$2b$10$abcdefghijklmnopqrstuuV6Q1NQx7NQx7NQx7NQx7NQx7NQx7NQx";

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  const rateLimitKey = {
    ip: req.ip,
    email,
    ipEmail: `${req.ip}:${email}`,
  };

  const isLimited = await loginRateLimiter.isLimited(rateLimitKey);

  if (isLimited) {
    return res.status(429).json({
      error: "Too many login attempts. Please try again later.",
    });
  }

  const user = await db.users.findUnique({
    where: { email },
  });

  const hashToCompare = user
    ? user.passwordHash
    : DUMMY_PASSWORD_HASH;

  const validPassword = await bcrypt.compare(password, hashToCompare);

  if (!user || !validPassword) {
    await loginRateLimiter.recordFailure(rateLimitKey);

    return res.status(401).json({
      error: "Email or password is incorrect",
    });
  }

  await loginRateLimiter.recordSuccess(rateLimitKey);

  return res.json({
    token: signJwt({ userId: user.id, role: user.role }),
  });
});
```

`loginRateLimiter` is conceptual here. In a real distributed Node.js backend, this should usually be backed by a shared store such as Redis so limits work across multiple server instances.

## Backend Security Rule

For login APIs:

- Do not reveal whether an email exists.
- Use the same `401 Unauthorized` response for missing user and wrong password.
- Reduce timing differences between authentication failure paths.
- Use a real dummy bcrypt hash with the same cost factor as production hashes.
- Enforce rate limits before expensive bcrypt work.
- Record failed attempts after failed authentication.
- Reset relevant counters after successful authentication.
- Use multiple throttling dimensions such as IP, email, and IP + email.
- Return generic `429 Too Many Requests` when throttled.
- Do not reveal account lockout or account existence state.

Authentication answers:

```txt
Are these credentials valid?
```

Safe authentication behavior also asks:

```txt
What does the failure response reveal to an attacker?
```

A secure login endpoint must protect both.
