# Day 3 Vulnerability Note: Broken Function Level Authorization

## Vulnerability Type

Broken Function Level Authorization / BFLA

## Core Idea

Broken Function Level Authorization happens when a user can access a function or action they should not be allowed to use.

In Day 1 and Day 2, the issue was:

```text
Can this user access this specific object?
```

For BFLA, the issue is:

```text
Can this user perform this action at all?
```

Example:

```text
A customer should not be able to delete users.
Only an admin should be able to delete users.
```

## Vulnerable Pattern

```javascript
app.delete("/api/admin/users/:userId", authMiddleware, async (req, res) => {
  await userService.deleteUser(req.params.userId);

  return res.json({ message: "User deleted" });
});
```

This route uses `authMiddleware`, so it verifies that the user is logged in.

However, it does not check whether the authenticated user has the `admin` role.

## Why It Is Insecure

Authentication only proves who the user is.

It does not prove that the user is allowed to perform an admin-only function.

A dangerous assumption is:

```text
Valid JWT = allowed to use admin APIs
```

The secure assumption should be:

```text
Valid JWT + required role or permission = allowed to use the function
```

If this check is missing, any authenticated user may be able to call sensitive admin endpoints such as:

```http
DELETE /api/admin/users/:userId
```

This can lead to unauthorized user deletion, privilege abuse, data loss, or account takeover.

## Secure Express Route

A safer route should authenticate the user first, then authorize the user before running the dangerous action.

```javascript
app.delete(
  "/api/admin/users/:userId",
  authMiddleware,
  requireRole("admin"),
  async (req, res) => {
    await userService.deleteUser(req.params.userId);

    return res.json({ message: "User deleted" });
  }
);
```

The order matters:

```text
authMiddleware
↓
requireRole("admin")
↓
deleteUser(...)
```

The delete action should only run after the user has passed both authentication and authorization checks.

## Role-Based Authorization Middleware

```javascript
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
};
```

This middleware checks whether the authenticated user has the required role.

Example usage:

```javascript
requireRole("admin")
```

This means:

```text
Only users with role admin can continue to the route handler.
```

## 401 vs 403

Use `401 Unauthorized` when the user is not authenticated.

Examples:

```text
Missing token
Invalid token
Expired token
No req.user available
```

Use `403 Forbidden` when the user is authenticated but does not have enough permission.

Example:

```text
A logged-in customer tries to call an admin-only delete API.
```

Simple rule:

```text
Missing or invalid identity = 401
Valid identity but insufficient permission = 403
```

## Bad Authorization Order

This is insecure:

```javascript
app.delete("/api/admin/users/:userId", authMiddleware, async (req, res) => {
  await userService.deleteUser(req.params.userId);

  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }

  return res.json({ message: "User deleted" });
});
```

The problem is that the dangerous action happens before the authorization check.

Even if the API returns `403 Forbidden`, the user may already be deleted.

Authorization must happen before side effects.

Correct order:

```text
Authenticate user
↓
Authorize function
↓
Perform dangerous action
```

Wrong order:

```text
Authenticate user
↓
Perform dangerous action
↓
Check authorization
```

## Regression Test

### Test Name

Authenticated customer cannot perform admin-only user deletion

### Given

User A is authenticated with role `customer`.

The API endpoint requires role `admin`.

User with ID `10` exists.

### When

User A sends the following request:

```http
DELETE /api/admin/users/10
Authorization: Bearer JWT_A
```

### Then

The API returns:

```http
403 Forbidden
```

User with ID `10` is not deleted.

## Security Test Notes

A strong BFLA test should verify both:

```text
The response status is correct.
The dangerous side effect did not happen.
```

It is not enough to only check for `403 Forbidden`.

The test must also confirm that the target user still exists after the request.

## Key Learning

Authentication answers:

```text
Who are you?
```

Function-level authorization answers:

```text
Are you allowed to perform this action?
```

Admin APIs must not rely only on login checks.

Sensitive functions should be protected with explicit role or permission checks.

A secure admin route should separate responsibilities:

```text
authMiddleware = verifies identity
requireRole("admin") = checks permission
route handler = performs the business action
```

The most important rule from Day 3:

```text
Authorization must happen before the dangerous action.
```