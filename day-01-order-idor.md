Security test: 1. Login as User A and get JWT_A. 
2. Go to order section and click on any order to get details 
3. From network tab review the API of GET which is like this /api/orders/{orderId} 
4. Now copy this orderId 
5. Login with any other user (B)
6. Using this user's token, send request like below 
     GET /api/orders/{userA_orderId} 
     Authorization: Bearer JWT_B 

Expected secure result:
   It should return 403 Forbidden or 404 Not Found.

Vulnerable observed result:
The API returns User A’s order details to User B, which proves broken object-level authorization / IDOR.
