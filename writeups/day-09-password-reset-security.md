# Day 9 - Password Reset Security

## Objective

Understand why a password reset flow is not safe just because the OTP matches.

Key lesson:

```txt
A password reset OTP must be valid, single-use, unexpired, attempt-limited, safely stored, and consumed atomically.
```

A secure password reset flow must protect against:

```txt
OTP brute force
OTP replay
expired OTP usage
plain-text OTP exposure
account enumeration
race conditions
reset request ambiguity
email/OTP bombing
```

## Vulnerable Pattern

This endpoint accepts an email, OTP, and new password. It checks whether a reset row exists with the same email and OTP, then changes the password.

```js
import express from "express";
import bcrypt from "bcrypt";

const app = express();
app.use(express.json());

app.post("/api/password-reset/confirm", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (
    typeof email !== "string" ||
    typeof otp !== "string" ||
    typeof newPassword !== "string"
  ) {
    return res.status(400).json({ error: "Invalid request" });
  }

  const resetRequest = await db.passwordResets.findFirst({
    where: {
      email,
      otp,
    },
  });

  if (!resetRequest) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);

  await db.users.update({
    where: { email },
    data: { passwordHash },
  });

  return res.json({ message: "Password reset successful" });
});
```

The dangerous lookup is:

```js
const resetRequest = await db.passwordResets.findFirst({
  where: {
    email,
    otp,
  },
});
```

This proves only:

```txt
A reset row exists with this email and OTP.
```

It does not prove:

```txt
The OTP has not expired.
The OTP has not already been used.
The OTP has not exceeded max attempts.
The OTP was stored safely.
The reset request is the intended reset request.
The operation is safe against concurrent replay.
```

## Risk 1 - OTP Brute Force

A 6-digit OTP has only:

```txt
000000 to 999999
```

That is 1,000,000 possible values.

If the endpoint has no attempt limit or rate limiting, an attacker can repeatedly try OTPs for a known email until one succeeds.

A secure reset confirmation flow needs:

```txt
attempt counter
maximum allowed attempts
rate limiting
generic failure response
```

## Risk 2 - OTP Replay

If a valid OTP is not marked as used after password reset, the same OTP may be reused.

A password reset OTP must be single-use.

After a successful password reset, mark the reset request as consumed:

```js
await db.passwordResets.update({
  where: { id: resetRequest.id },
  data: {
    consumedAt: new Date(),
  },
});
```

`consumedAt` or `usedAt` is clearer than only changing `expiresAt`, because it explicitly records that the reset request was already used.

## Risk 3 - Plain-Text OTP Storage

This table is unsafe:

```txt
passwordResets
--------------
id | email             | otp    | expiresAt            | usedAt
1  | keval@example.com | 493821 | 2026-06-01 12:30:00  | null
```

If the database leaks, the attacker can directly read active OTPs.

The database should store an OTP hash instead:

```txt
passwordResets
--------------
id | email             | otpHash | expiresAt            | consumedAt | attempts
1  | keval@example.com | ...     | 2026-06-01 12:30:00  | null       | 0
```

Because OTPs are short, a simple unsalted hash like `SHA256(otp)` is weak if the database leaks. An attacker can brute-force all 1,000,000 OTPs offline.

A stronger pattern is:

```txt
otpHash = HMAC_SHA256(otp, server-side secret)
```

or another secure server-side keyed hashing approach, combined with expiry and attempt limits.

## Valid Reset Request Conditions

A valid reset request should prove:

```txt
email matches
otpHash matches
not consumed
not expired
attempts below max
```

Example lookup when checking a known correct OTP hash:

```js
where: {
  email,
  otpHash,
  consumedAt: null,
  expiresAt: {
    gt: new Date(),
  },
  attempts: {
    lt: MAX_ATTEMPTS,
  },
}
```

However, if the lookup includes `otpHash` first and the submitted OTP is wrong, the database returns no row. Then the backend does not know which reset request should have its attempt counter incremented.

## Correct Order for OTP Attempt Counting

To count wrong OTP attempts, do not use `otpHash` in the first lookup.

A safer order:

```txt
1. Validate email, otp, newPassword, and resetRequestId input shape.
2. Find the reset request by resetRequestId and email.
3. If no reset request exists, return a generic 400 error.
4. Check consumedAt is null, expiresAt is still valid, and attempts < MAX_ATTEMPTS.
5. Compute otpHash from the submitted OTP.
6. Compare the computed otpHash with the stored otpHash.
7. If OTP does not match, increment attempts and return a generic 400 error.
8. If OTP matches, update the password hash and mark the reset request consumed in one transaction.
9. Return password reset successful.
```

This lets the backend count failed OTP attempts even when the submitted OTP is wrong.

## Reset Request Ambiguity

If the backend looks up the reset request only by email, a problem can happen when the same user requests two OTPs in a row.

Example:

```txt
Reset request 1: OTP 111111
Reset request 2: OTP 222222
```

If the confirm API does:

```js
findFirst({
  where: { email }
})
```

the backend may pick:

```txt
the older reset request
the newer reset request
the wrong row depending on database ordering
```

This can cause unsafe behavior:

```txt
Old OTP may still work.
Wrong reset request may get attempts incremented.
A successful reset may consume only one row while another remains valid.
```

Safer design:

```txt
1. When creating a new OTP, invalidate previous active reset requests for that email.
2. Tie the OTP to one resetRequestId.
3. Confirm password reset using resetRequestId + email + OTP.
```

Example lookup:

```js
where: {
  id: resetRequestId,
  email,
}
```

Then verify:

```txt
consumedAt is null
expiresAt is still valid
attempts < MAX_ATTEMPTS
submitted otpHash matches stored otpHash
```

## Race Condition Risk

Two requests may hit the server at almost the same time with the same valid OTP:

```txt
Request A: OTP 493821
Request B: OTP 493821
```

Both may read the reset request before either one marks it consumed:

```txt
consumedAt = null
otpHash matches
expiresAt still valid
```

If password update and `consumedAt` update are not done atomically, both requests may pass.

This breaks the rule:

```txt
A reset OTP must be single-use.
```

The final password may become whichever request writes last.

## Atomic Consume Pattern

The reset operation should be atomic.

Safer pattern:

```txt
In one transaction, consume the valid reset request only if consumedAt is still null, then update the password.
```

Inside the transaction, use a guarded update:

```js
const consumed = await tx.passwordResets.updateMany({
  where: {
    id: resetRequest.id,
    consumedAt: null,
    expiresAt: {
      gt: new Date(),
    },
    attempts: {
      lt: MAX_ATTEMPTS,
    },
  },
  data: {
    consumedAt: new Date(),
  },
});
```

Then check:

```js
if (consumed.count !== 1) {
  throw new Error("Invalid or expired reset request");
}
```

If `consumed.count` is `0`, do not update the password. The request was no longer valid at the moment of update.

The API should return a generic failure response:

```json
{
  "error": "Invalid or expired reset request"
}
```

## Regression Test 1

### Test Name

Password reset OTP must be single-use.

### Given

A valid password reset request exists for:

```txt
keval@example.com
```

The reset request has:

```txt
resetRequestId = reset_123
otp = 493821
consumedAt = null
expiresAt is still in the future
attempts < MAX_ATTEMPTS
```

The user's current password is not:

```txt
NewPassword@123
```

### When

The user submits the valid OTP for the first time:

```http
POST /api/password-reset/confirm
Content-Type: application/json

{
  "resetRequestId": "reset_123",
  "email": "keval@example.com",
  "otp": "493821",
  "newPassword": "NewPassword@123"
}
```

### Then

The API returns:

```http
200 OK
```

The user's password is updated to the hash of:

```txt
NewPassword@123
```

The reset request is marked as consumed:

```txt
consumedAt != null
```

### When

The same OTP and reset request are submitted again:

```http
POST /api/password-reset/confirm
Content-Type: application/json

{
  "resetRequestId": "reset_123",
  "email": "keval@example.com",
  "otp": "493821",
  "newPassword": "AttackerPassword@999"
}
```

### Then

The API returns a generic failure response:

```http
400 Bad Request
```

The response body does not reveal whether the OTP was already used, expired, invalid, or raced.

The user's password must not be changed to:

```txt
AttackerPassword@999
```

The previously consumed reset request must not be accepted again.

The OTP must not be replayable after successful use.

## Password Reset Request Enumeration

The reset request endpoint can also leak account existence.

Vulnerable example:

```js
app.post("/api/password-reset/request", async (req, res) => {
  const { email } = req.body;

  const user = await db.users.findUnique({
    where: { email },
  });

  if (!user) {
    return res.status(404).json({
      error: "No account found with this email",
    });
  }

  const otp = generateSixDigitOtp();

  await db.passwordResets.create({
    data: {
      email,
      otpHash: hashOtp(otp),
      expiresAt: addMinutes(new Date(), 10),
      consumedAt: null,
      attempts: 0,
    },
  });

  await sendResetOtpEmail(email, otp);

  return res.json({
    message: "Password reset OTP sent",
  });
});
```

Dangerous response:

```js
return res.status(404).json({
  error: "No account found with this email",
});
```

This creates account enumeration:

```txt
Existing email     -> Password reset OTP sent
Non-existing email -> No account found
```

The different status codes also leak account existence:

```txt
Existing email     -> 200
Non-existing email -> 404
```

## Safer Password Reset Request Behavior

The API should return the same response whether the email exists or not.

Relevant control flow:

```js
const user = await db.users.findUnique({
  where: { email },
});

if (user) {
  const otp = generateSixDigitOtp();

  await db.$transaction(async (tx) => {
    await tx.passwordResets.updateMany({
      where: {
        email: user.email,
        consumedAt: null,
      },
      data: {
        consumedAt: new Date(),
      },
    });

    await tx.passwordResets.create({
      data: {
        email: user.email,
        otpHash: hashOtp(otp),
        expiresAt: addMinutes(new Date(), 10),
        consumedAt: null,
        attempts: 0,
      },
    });
  });

  await sendResetOtpEmail(user.email, otp);
}

return res.json({
  message: "If an account exists for this email, a password reset OTP will be sent.",
});
```

Response behavior:

```txt
Existing email     -> 200 + same generic message
Non-existing email -> 200 + same generic message
```

The API no longer reveals account existence through:

```txt
status code
error message
success message
response body
```

## Password Reset Request Rate Limiting

Even with generic responses, the password reset request endpoint must be rate-limited.

Without rate limiting, attackers can cause:

```txt
email/OTP bombing against a victim
mail provider quota abuse
OTP table/storage growth
CPU/DB load from repeated reset creation
user harassment through repeated reset emails
```

Good rate-limit dimensions:

```txt
IP
email
IP + email
device fingerprint if available
```

Device fingerprint can help, but it should not be the only control because headers and browser/device signals can be spoofed.

Better rule:

```txt
Use layered rate limits: per IP, per email, and per IP+email.
```

## Regression Test 2

### Test Name

Password reset request must not reveal whether an email exists.

### Given

`keval@example.com` is a valid user account.

`random-user-123@example.com` is not a valid user account.

The password reset request endpoint accepts:

```http
POST /api/password-reset/request
```

The API must not reveal whether the submitted email belongs to an existing account.

### When

A password reset request is made for an existing email:

```http
POST /api/password-reset/request
Content-Type: application/json

{
  "email": "keval@example.com"
}
```

### Then

The API returns:

```http
200 OK
```

The response body is generic:

```json
{
  "message": "If an account exists for this email, a password reset OTP will be sent."
}
```

An OTP is generated, stored, and sent only because the account exists.

### When

A password reset request is made for a non-existing email:

```http
POST /api/password-reset/request
Content-Type: application/json

{
  "email": "random-user-123@example.com"
}
```

### Then

The API returns:

```http
200 OK
```

The response body is the same generic response:

```json
{
  "message": "If an account exists for this email, a password reset OTP will be sent."
}
```

No OTP is generated.

No OTP email is sent.

The response must not reveal whether the email exists through:

```txt
status code
error message
success message
response body
```

From the attacker's perspective, both responses must be indistinguishable.

## Secure Confirm Flow Summary

A secure `/api/password-reset/confirm` flow should:

```txt
1. Validate input shape.
2. Find reset request by resetRequestId and email.
3. Reject with a generic error if the request does not exist.
4. Check consumedAt is null.
5. Check expiresAt is still in the future.
6. Check attempts < MAX_ATTEMPTS.
7. Compute otpHash from submitted OTP.
8. Compare submitted otpHash to stored otpHash.
9. If OTP is wrong, increment attempts and return a generic error.
10. If OTP is correct, atomically consume the reset request and update password.
11. Return success.
```

## Backend Security Rule

For password reset APIs:

- Do not store OTPs in plain text.
- Store an OTP hash, preferably using a server-side secret.
- OTPs must expire.
- OTPs must be single-use.
- Track failed attempts.
- Rate-limit reset request and reset confirm endpoints.
- Do not reveal whether an email exists.
- Do not look up reset requests by email only when multiple reset requests may exist.
- Prefer resetRequestId + email + OTP.
- Invalidate previous active reset requests when creating a new OTP.
- Use generic error messages for invalid, expired, consumed, or raced reset attempts.
- Atomically consume the reset request and update the password.
- Never allow two concurrent requests to use the same OTP successfully.

Password reset asks:

```txt
Has this requester proven temporary control of the account recovery channel safely?
```

The OTP is only safe if the backend enforces expiry, attempts, single-use, hashing, and atomic consumption.
