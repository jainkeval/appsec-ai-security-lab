# Day 4 Vulnerability Note: Mass Assignment in Profile Update API

## Vulnerability Type

Mass Assignment

## Core Idea

Mass assignment happens when a backend blindly saves fields from the request body without checking whether the user is allowed to update those fields.

A user may be allowed to update normal profile fields such as:

```text
displayName
bio
avatarUrl
```

But the same user should not be allowed to update protected fields such as:

```text
role
isAdmin
accountStatus
emailVerified
userId
permissions
```

The security rule is:

```text
Never blindly persist the full request body.
Only save fields that are explicitly allowed.
```

## Vulnerable Pattern

```javascript
app.patch("/api/me/profile", authMiddleware, async (req, res) => {
  const updatedUser = await userRepository.update(req.user.id, req.body);

  return res.json(updatedUser);
});
```

This looks convenient because the backend directly passes `req.body` into the update function.

However, this is dangerous because the client controls the request body.

A normal user may send:

```json
{
  "displayName": "KEVAL",
  "bio": "Coder"
}
```

But an attacker may send:

```json
{
  "displayName": "KEVAL",
  "bio": "Coder",
  "role": "admin",
  "isAdmin": true
}
```

If the backend blindly saves `req.body`, protected fields such as `role` or `isAdmin` may be updated.

## Why It Is Insecure

The backend is trusting client-controlled input too much.

Authentication proves who the user is, but it does not mean the user can update every field on their own account.

A dangerous assumption is:

```text
Authenticated user + req.body = safe update
```

The secure assumption should be:

```text
Authenticated user + allowlisted fields only = safe update
```

The backend must decide which fields are allowed.

The client must not decide.

## Malicious Test Payload

A tester can check for mass assignment by sending allowed fields together with protected fields.

Example request:

```http
PATCH /api/me/profile
Authorization: Bearer JWT_A
Content-Type: application/json
```

Request body:

```json
{
  "role": "admin",
  "displayName": "KEVAL",
  "bio": "Coder",
  "isAdmin": true
}
```

The fields `displayName` and `bio` are normal profile fields.

The fields `role` and `isAdmin` are suspicious privilege-related fields.

## Expected Secure Behavior

The API should not update protected fields.

Only allowed fields should be updated:

```json
{
  "displayName": "KEVAL",
  "bio": "Coder"
}
```

The API must not save:

```json
{
  "role": "admin",
  "isAdmin": true
}
```

## API Behavior Decision

If the request body contains disallowed protected fields, the API should return:

```http
400 Bad Request
```

It should not update anything.

Reason:

Protected fields such as `role`, `isAdmin`, `accountStatus`, and `emailVerified` must not be controlled by the client.

If such fields are present in the request body, the backend should fail closed and reject the request instead of silently ignoring the attack attempt.

Fail closed means:

```text
When something suspicious happens, deny the request instead of trying to continue safely.
```

## Secure Pattern: Detect Protected Fields

Protected fields:

```javascript
const protectedFields = ["role", "isAdmin", "accountStatus", "emailVerified"];
```

Detect whether the request body contains any protected fields:

```javascript
const attemptedProtectedFields = protectedFields.filter((field) =>
  Object.prototype.hasOwnProperty.call(req.body, field)
);
```

If protected fields are present, reject the request:

```javascript
if (attemptedProtectedFields.length > 0) {
  return res.status(400).json({
    message: "Protected fields cannot be updated",
    fields: attemptedProtectedFields,
  });
}
```

## Why Use hasOwnProperty.call()

This code is more production-safe:

```javascript
Object.prototype.hasOwnProperty.call(req.body, field)
```

It checks whether the field exists directly on `req.body`.

This is safer than:

```javascript
field in req.body
```

because the `in` operator checks both the object itself and its prototype chain.

For security-sensitive request validation, the backend should check what the client directly sent in the request body.

Also, avoid this:

```javascript
req.body.hasOwnProperty(field)
```

because `req.body` may be unusual or attacker-influenced.

For example, it may not have `hasOwnProperty`, or the client may send a field named `hasOwnProperty`.

The safer pattern is:

```javascript
Object.prototype.hasOwnProperty.call(req.body, field)
```

## Secure Pattern: Build an Allowlist

Allowed profile fields:

```text
displayName
bio
avatarUrl
```

Build an update object using only these fields:

```javascript
const allowedUpdates = {};

if (Object.prototype.hasOwnProperty.call(req.body, "displayName")) {
  allowedUpdates.displayName = req.body.displayName;
}

if (Object.prototype.hasOwnProperty.call(req.body, "bio")) {
  allowedUpdates.bio = req.body.bio;
}

if (Object.prototype.hasOwnProperty.call(req.body, "avatarUrl")) {
  allowedUpdates.avatarUrl = req.body.avatarUrl;
}
```

Then update using only `allowedUpdates`:

```javascript
const updatedUser = await userRepository.update(req.user.id, allowedUpdates);
```

Do not update using the full request body:

```javascript
await userRepository.update(req.user.id, req.body);
```

That would bring the mass-assignment bug back.

## Secure Express Route

```javascript
app.patch("/api/me/profile", authMiddleware, async (req, res) => {
  const protectedFields = ["role", "isAdmin", "accountStatus", "emailVerified"];

  const attemptedProtectedFields = protectedFields.filter((field) =>
    Object.prototype.hasOwnProperty.call(req.body, field)
  );

  if (attemptedProtectedFields.length > 0) {
    return res.status(400).json({
      message: "Protected fields cannot be updated",
      fields: attemptedProtectedFields,
    });
  }

  const allowedUpdates = {};

  if (Object.prototype.hasOwnProperty.call(req.body, "displayName")) {
    allowedUpdates.displayName = req.body.displayName;
  }

  if (Object.prototype.hasOwnProperty.call(req.body, "bio")) {
    allowedUpdates.bio = req.body.bio;
  }

  if (Object.prototype.hasOwnProperty.call(req.body, "avatarUrl")) {
    allowedUpdates.avatarUrl = req.body.avatarUrl;
  }

  const updatedUser = await userRepository.update(req.user.id, allowedUpdates);

  return res.json(updatedUser);
});
```

## Regression Test

### Test Name

Only allowed profile attributes can be updated

### Given

User A is authenticated.

User A is allowed to update their own profile.

Only the following fields are allowed to be updated:

```text
displayName
bio
avatarUrl
```

Protected fields must not be updated by the client:

```text
role
isAdmin
accountStatus
emailVerified
```

### When

User A sends the following request:

```http
PATCH /api/me/profile
Authorization: Bearer JWT_A
Content-Type: application/json
```

Request body:

```json
{
  "displayName": "KEVAL",
  "bio": "Coder",
  "role": "admin",
  "isAdmin": true
}
```

### Then

The API returns:

```http
400 Bad Request
```

The API does not update any user fields.

The protected fields remain unchanged:

```text
role
isAdmin
```

User A does not become an admin.

## Alternative Test for Ignore-Unknown Design

Some APIs choose to silently ignore unknown harmless fields for backward compatibility.

However, for protected security-sensitive fields, this writeup chooses the stricter behavior:

```text
Reject the request with 400 Bad Request.
Update nothing.
```

This is safer because attempts to modify protected fields should not look like normal successful requests.

## Key Learning

Mass assignment is caused by blindly trusting the full request body.

A vulnerable pattern is:

```javascript
userRepository.update(req.user.id, req.body);
```

A secure pattern is:

```javascript
userRepository.update(req.user.id, allowedUpdates);
```

The backend must define what can be changed.

The client should never be allowed to decide which database fields are updated.

The most important rule from Day 4:

```text
Use an allowlist for user-editable fields.
Reject protected fields.
Never persist req.body directly.
```
