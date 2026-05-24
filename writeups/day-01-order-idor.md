# Day 1 Vulnerability Note: Order ID Authorization Bug

## Vulnerability Type

Broken Object Level Authorization / IDOR

## Asset

Order details belonging to a specific user, including order items, order status, shipping details, and other sensitive customer information.

## Entry Point

```http
GET /api/orders/{orderId}
Authorization: Bearer <jwt>
```

## Abuse Case

An authenticated user can change the `orderId` in the API request and try to access another user's order details.

## Impact

If the backend only checks whether the JWT is valid but does not verify ownership of the order, one user may be able to view another user's private order details.

This is an authorization failure at the object level.

## Backend Fix

The backend must verify that the authenticated user owns the requested order or has explicit permission to access it.

Example secure logic:

```text
Valid JWT + order belongs to authenticated user = allow access
Valid JWT + order does not belong to authenticated user = deny access
```

The ownership check must happen on the server side. The backend should never trust the `orderId` sent by the client without verifying access.

## Security Test

1. Login as User A and get `JWT_A`.
2. Go to the order section and click on any order to get its details.
3. From the browser network tab, review the GET API request:

```http
GET /api/orders/{orderId}
Authorization: Bearer JWT_A
```

4. Copy User A's `orderId`.
5. Login as another user, User B, and get `JWT_B`.
6. Using User B's token, send the request:

```http
GET /api/orders/{userA_orderId}
Authorization: Bearer JWT_B
```

## Expected Secure Result

The API should return:

```http
403 Forbidden
```

or:

```http
404 Not Found
```

The API should not return User A's order details to User B.

## Vulnerable Observed Result

The API returns User A's order details to User B.

This proves broken object-level authorization / IDOR.

## Key Learning

Authentication confirms who the user is.

Authorization confirms whether the user is allowed to access a specific object.

A valid JWT alone is not enough to access every resource.