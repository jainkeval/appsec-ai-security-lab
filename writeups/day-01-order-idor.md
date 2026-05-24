# Day 1 Vulnerability Note: Order ID Authorization Bug

## Vulnerability Type

Broken Object Level Authorization / IDOR

## Asset

Order details belonging to a specific user, including order items, order status, shipping details, and other sensitive customer information.

## Entry Point

```http
GET /api/orders/{orderId}
Authorization: Bearer <jwt>