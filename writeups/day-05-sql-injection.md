# Day 5 Vulnerability Note: SQL Injection and Safe Query Building

## Vulnerability Type

SQL Injection

## Core Idea

SQL injection happens when untrusted user input is mixed directly into a SQL query string.

The database may then treat attacker-controlled input as part of the SQL command instead of treating it as normal data.

The main rule is:

```text
User-controlled values should be passed using parameterized queries / bind variables.
```

Unsafe pattern:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  WHERE name LIKE '%${search}%'
`;
```

Safe pattern:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  WHERE name LIKE ?
`;

const params = [`%${search}%`];

const products = await db.query(sql, params);
```

## Vulnerable Search Endpoint

```javascript
app.get("/api/products/search", authMiddleware, async (req, res) => {
  const search = req.query.q;

  const sql = `
    SELECT id, name, price
    FROM products
    WHERE name LIKE '%${search}%'
  `;

  const products = await db.query(sql);

  return res.json(products);
});
```

## Why It Is Insecure

The value from `req.query.q` is controlled by the client.

If it is inserted directly into the SQL string, an attacker may be able to change the meaning of the query.

Normal input:

```text
q=phone
```

Resulting SQL:

```sql
SELECT id, name, price
FROM products
WHERE name LIKE '%phone%'
```

Malicious input:

```text
q=x%' OR '1'='1' --
```

Resulting SQL:

```sql
SELECT id, name, price
FROM products
WHERE name LIKE '%x%' OR '1'='1' --%'
```

The dangerous part is:

```sql
OR '1'='1'
```

That condition is always true, so the query may return all products.

The `--` comments out the rest of the SQL, preventing the trailing characters from breaking the query.

## Secure Search Query

Use a parameterized query:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  WHERE name LIKE ?
`;

const params = [`%${search}%`];

const products = await db.query(sql, params);
```

This separates SQL structure from user input.

```text
SQL structure: SELECT ... WHERE name LIKE ?
User value:    %phone%
```

The database driver treats the user input as a value, not executable SQL.

## Why the Wildcards Are in the Parameter

Correct:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  WHERE name LIKE ?
`;

const params = [`%${search}%`];
```

Incorrect:

```sql
WHERE name LIKE '%?%'
```

In the incorrect version, `?` is inside quotes and may be treated as literal text instead of a bind placeholder.

The placeholder should stand alone in SQL.

The `%` wildcard characters should be included in the parameter value.

## Regression Test: SQL Injection Search Payload

### Test Name

Search API treats SQL injection payload as plain text

### Given

User A is authenticated.

User A is allowed to use the product search API.

### When

User A sends:

```http
GET /api/products/search?q=x%' OR '1'='1' --
Authorization: Bearer JWT_A
```

### Then

The API does not return all products.

The API treats the payload as a normal search string.

The API returns only products whose names literally match the search text, or returns an empty array if none match.

## Vulnerable Login Query

```javascript
const email = req.body.email;
const password = req.body.password;

const sql = `
  SELECT id, email, role
  FROM users
  WHERE email = '${email}'
  AND password = '${password}'
`;

const user = await db.query(sql);
```

This is vulnerable because both `email` and `password` are inserted directly into the SQL string.

## SQL-Injection-Safe Login Query

For the SQL injection part, use bind parameters:

```javascript
const sql = `
  SELECT id, email, role
  FROM users
  WHERE email = ?
  AND password = ?
`;

const params = [email, password];

const user = await db.query(sql, params);
```

This prevents email and password input from becoming executable SQL.

However, this is still not a secure real-world login design because it suggests comparing plaintext passwords.

## Real Login Design with Password Hashing

A real backend should not store plaintext passwords.

It should store a slow password hash using a password hashing library such as:

```text
bcrypt
argon2
scrypt
```

A better login flow is:

```javascript
const user = await userRepository.findByEmail(email);

if (!user) {
  // return 401 Unauthorized with generic "Invalid email or password"
}

// verify submitted password against stored password hash

if (!passwordMatches) {
  // return 401 Unauthorized with generic "Invalid email or password"
}

// create session or issue JWT
// return login success response
```

Use the same generic error for both missing user and wrong password:

```text
Invalid email or password
```

This avoids revealing whether an email exists.

## Safe Repository Query for findByEmail

```javascript
const sql = `
  SELECT id, email, role, password_hash
  FROM users
  WHERE email = ?
`;

const params = [email];

const user = await db.query(sql, params);
```

The `password_hash` is selected only for server-side verification.

It must never be returned to the client.

## Dynamic ORDER BY Risk

Some SQL injection risks are not simple values.

Example vulnerable code:

```javascript
const sort = req.query.sort;

const sql = `
  SELECT id, name, price
  FROM products
  ORDER BY ${sort}
`;

const products = await db.query(sql);
```

The suspicious part is:

```javascript
ORDER BY ${sort}
```

The client controls SQL structure.

For normal values such as email, search text, and password, use bind parameters.

For SQL structure such as column names and sort direction, use allowlist validation.

## Safe Sort Field Allowlist

Allowed sort fields:

```javascript
const allowedSortFields = ["name", "price", "createdAt"];
```

Input:

```javascript
const sort = req.query.sort || "name";
```

Validation:

```javascript
if (!allowedSortFields.includes(sort)) {
  return res.status(400).json({ message: "Invalid sort field" });
}
```

Only after validation should the backend use `sort` in SQL:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  ORDER BY ${sort}
`;

const products = await db.query(sql);
```

This raw interpolation is acceptable only because `sort` was validated against a strict allowlist first.

## Safe Sort Direction Allowlist

Vulnerable version:

```javascript
const sort = req.query.sort || "name";
const direction = req.query.direction || "asc";

const sql = `
  SELECT id, name, price
  FROM products
  ORDER BY ${sort} ${direction}
`;
```

Both `sort` and `direction` shape the SQL query, so both need allowlists.

Allowed directions:

```javascript
const allowedDirections = ["asc", "desc"];
```

Validation:

```javascript
if (!allowedDirections.includes(direction)) {
  return res.status(400).json({ message: "Invalid sort direction" });
}
```

After both `sort` and `direction` are validated:

```javascript
const sql = `
  SELECT id, name, price
  FROM products
  ORDER BY ${sort} ${direction}
`;

const products = await db.query(sql);
```

## Regression Test: Invalid Sort Direction

### Test Name

Product API rejects invalid sort direction

### Given

User A is authenticated.

User A is allowed to use the products API.

The API only allows sort directions:

```text
asc
desc
```

### When

User A sends:

```http
GET /api/products?sort=price&direction=drop table users
Authorization: Bearer JWT_A
```

### Then

The API returns:

```http
400 Bad Request
```

The backend rejects the request before building or executing the SQL query.

The invalid SQL-shaping input does not reach the database.

## Key Learning

There are two main cases:

```text
User-controlled values -> use parameterized queries / bind variables.
SQL structure input -> use allowlist validation.
```

Examples of user-controlled values:

```text
email
password
search text
product ID
order ID
```

Examples of SQL structure input:

```text
sort column
sort direction
table name
selected field name
```

For values:

```javascript
WHERE email = ?
```

with:

```javascript
const params = [email];
```

For SQL structure:

```javascript
const allowedSortFields = ["name", "price", "createdAt"];

if (!allowedSortFields.includes(sort)) {
  return res.status(400).json({ message: "Invalid sort field" });
}
```

The most important rule from Day 5:

```text
Never build SQL by directly mixing untrusted input into query strings.
Use parameters for values.
Use allowlists for SQL structure.
```
