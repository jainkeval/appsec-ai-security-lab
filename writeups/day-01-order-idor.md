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

An authenticated user can change the orderId in the API request and try to access another user's order details.

## Impact

If the backend only checks whether the JWT is valid but does not verify ownership of the order, one user may be able to view another user's private order details.

This is an authorization failure at the object level.

## Backend Fix

The backend must verify that the authenticated user owns the requested order or has explicit permission to access it.

Example secure logic:

Valid JWT + order belongs to authenticated user = allow access
Valid JWT + order does not belong to authenticated user = deny access

The ownership check must happen on the server side. The backend should never trust the orderId sent by the client without verifying access.

# Security Test

Login as User A and get JWT_A.
Go to the order section and click on any order to get its details.
From the browser network tab, review the GET API request:
```
GET /api/orders/{orderId}
Authorization: Bearer JWT_A
```
Copy User A's orderId.
Login as another user, User B, and get JWT_B.
Using User B's token, send the request:
```
GET /api/orders/{userA_orderId}
Authorization: Bearer JWT_B
```

# Expected Secure Result

The API should return: