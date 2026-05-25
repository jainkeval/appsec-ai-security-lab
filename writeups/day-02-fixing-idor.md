# Day 2 Vulnerability Fix Note: Fixing IDOR with Secure Object Lookup

## Vulnerability Type

Broken Object Level Authorization / IDOR

## Vulnerable Pattern

```javascript
const getOrder = (orderId) => db.getOrder(orderId);
```

This pattern is insecure because the backend fetches the order using only `orderId`.

The lookup does not include the authenticated user's identity, so the backend checks whether the order exists but does not check whether the current user is allowed to access that specific order.

A similar weak SQL pattern would be:

```sql
SELECT *
FROM orders
WHERE id = :orderId;
```

This query only answers:

```text
Does this order exist?
```

It does not answer:

```text
Can this authenticated user access this order?
```

## Why It Is Insecure

Authentication only proves who the user is.

It does not automatically prove that the user has permission to access every object in the system.

This is an object-level authorization issue because the backend must verify access to the specific order being requested, not just verify that the user has a valid JWT.

A dangerous backend assumption is:

```text
Valid JWT = allowed to access any order
```

The secure assumption should be:

```text
Valid JWT + order belongs to authenticated user = allow access
```

## Secure Controller Logic

The backend should get the authenticated user's ID from the server-side security context.

The user ID should not be accepted from the request body, query parameter, or path parameter for this authorization decision.

Example secure controller logic:

```java
@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    Long authenticatedUserId = securityContext.getUserId();

    return orderRepository.findByIdAndUserId(orderId, authenticatedUserId)
        .orElseThrow(() -> new NotFoundException("Order not found"));
}
```

The important part is this lookup:

```java
findByIdAndUserId(orderId, authenticatedUserId)
```

This ensures that the order is returned only if it exists and belongs to the authenticated user.

## Secure SQL / Repository Query

A secure lookup should include both the requested object ID and the authenticated user's ID.

```sql
SELECT order_id, user_id, order_name, order_status, created_at
FROM orders
WHERE order_id = :orderId
AND user_id = :authenticatedUserId;
```

This query answers both security questions:

```text
Does this order exist?
Can this authenticated user access this order?
```

If no matching row is found, the API should not return the order.

## 404 vs 403 Decision

For this type of user-owned resource, returning `404 Not Found` is often safer than returning `403 Forbidden`.

A `403 Forbidden` response can reveal that the order exists but belongs to someone else.

A `404 Not Found` response avoids confirming whether the order exists.

For example, if User B tries to access User A's valid order ID, the API should return:

```http
404 Not Found
```

This reduces the risk of object enumeration.
## Bad Fix: User ID from Request Header

```javascript
app.get("/api/me/orders/:orderId", async (req, res) => {
  const authenticatedUserId = req.headers["user-id"];
  const orderId = req.params.orderId;

  const order = await orderRepository.findByIdAndUserId(
    orderId,
    authenticatedUserId
  );

  if (!order) {
    return res.status(404).json({ message: "Not found" });
  }

  return res.json(order);
});
```

Why this is still vulnerable:

This looks safer because the query uses both `orderId` and `authenticatedUserId`.

However, the `authenticatedUserId` comes from `req.headers["user-id"]`, which is attacker-controlled input. A malicious user can manually send another user's ID in the request header and attempt to access that user's order.

This is a fake fix because the backend is still trusting identity data supplied by the client.

Secure rule:

The authenticated user ID must come from trusted server-side authentication middleware, not from headers, request body, query parameters, or path parameters.

A safer pattern is:

```javascript
const authenticatedUserId = req.user.id;
```

where `req.user` is populated only after the JWT or session has been verified by authentication middleware.

## Trusted Authentication Middleware

A secure IDOR fix depends on having a trusted authenticated user ID.

The backend should not get the user ID from:

```text
request headers
request body
query parameters
path parameters
```

These are client-controlled inputs.

Instead, the backend should get the authenticated user ID from verified authentication middleware.

## Bad Pattern: Using jwt.decode()

```javascript
const payload = jwt.decode(token);

req.user = {
  id: payload.userId,
};
```

This is insecure because `jwt.decode()` only reads the token payload.

It does not verify:

```text
signature
expiry
issuer
token integrity
```

An attacker may be able to forge a token payload such as:

```json
{
  "userId": 1,
  "role": "admin"
}
```

If the backend trusts `jwt.decode()`, it may treat attacker-controlled data as a real authenticated identity.

## Secure Pattern: Using jwt.verify()

```javascript
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    req.user = {
      id: payload.userId,
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};
```

This is safer because `jwt.verify()` validates the token before the backend trusts the payload.

Only after verification succeeds should the backend attach the user identity to the request:

```javascript
req.user = {
  id: payload.userId,
};
```

Then downstream route handlers can safely use:

```javascript
const authenticatedUserId = req.user.id;
```

## Key Security Rule

For authorization decisions, the authenticated user ID must come from trusted server-side authentication middleware.

It must not come from attacker-controlled inputs such as:

```javascript
req.headers["user-id"]
req.body.userId
req.params.userId
req.query.userId
```

A secure object lookup should use:

```text
orderId from request path + authenticatedUserId from verified middleware
```

Example:

```javascript
const order = await orderRepository.findByIdAndUserId(
  orderId,
  req.user.id
);
```

This protects against fake fixes where the query looks secure but the user identity still comes from the client.

## Regression Test

### Test Name

Authenticated user cannot access another user's order

### Given

User A owns order with ID `10`.

User B is authenticated.

User B does not own order with ID `10`.

### When

User B sends the following request:

```http
GET /api/orders/10
Authorization: Bearer JWT_B
```

### Then

The API returns:

```http
404 Not Found
```

The response body does not contain User A's order details.

Specifically, the response should not expose sensitive fields such as:

```text
orderId
userId
items
shipping address
payment-related fields
order status
```

## Key Learning

Never fetch sensitive user-owned data by object ID alone.

For user-owned resources, secure backend lookup should usually include:

```text
resourceId + authenticatedUserId
```

Authentication tells the backend who the user is.

Object-level authorization tells the backend whether that user can access the specific resource being requested.

A valid JWT is necessary, but it is not enough.
