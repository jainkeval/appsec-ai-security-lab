# Day 7A - Secure File Download Authorization

## Vulnerable Pattern

This endpoint does not use `exec()`, so it is not vulnerable to command injection in the same way as Day 6.

However, it still allows user-controlled input to decide which file is read.

```js
import express from "express";
import path from "path";
import fs from "fs/promises";

const app = express();

app.get("/api/documents/download", authMiddleware, async (req, res) => {
  try {
    const fileName = req.query.fileName;

    if (typeof fileName !== "string") {
      return res.status(400).json({ error: "Invalid file name" });
    }

    if (!/^[a-zA-Z0-9_-]+\.txt$/.test(fileName)) {
      return res.status(400).json({ error: "Invalid file name" });
    }

    const document = await db.documents.findFirst({
      where: {
        fileName: fileName,
      },
    });

    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    const fileContent = await fs.readFile(document.storagePath, "utf8");

    return res.type("text/plain").send(fileContent);
  } catch (err) {
    console.error("Document download failed:", err);
    return res.status(500).json({ error: "Could not download document" });
  }
});
```

The dangerous part is:

```js
const document = await db.documents.findFirst({
  where: {
    fileName: fileName,
  },
});
```

The query checks whether the file exists, but it does not check whether the authenticated user is allowed to access that file.

## Why This Is Vulnerable

Assume the database contains:

```txt
documents
---------
id | ownerUserId | fileName                | storagePath
1  | user_a      | customer-a-contract.txt | /safe/docs/a.txt
2  | user_b      | customer-b-contract.txt | /safe/docs/b.txt
```

User A sends:

```http
GET /api/documents/download?fileName=customer-b-contract.txt
Authorization: Bearer JWT_A
```

The filename is valid.

It does not contain:

```txt
../
/
\
;
&&
|
$()
```

But the API still has a security problem.

The backend has only proven:

```txt
A document with this filename exists.
```

It has not proven:

```txt
The authenticated user is allowed to access this specific document.
```

This is an authorization flaw.

A valid filename does not mean authorized access.

Authentication proves identity.  
Filename validation proves input shape.  
Authorization proves access rights.

This endpoint performs authentication and validation, but it misses object-level authorization.

## Security Risk

This is a file-access version of IDOR / BOLA.

The attacker is not trying to break the filename validation.  
The attacker is using a valid filename that belongs to another user.

Impact:

- User A may download User B's private documents.
- Valid files can be accessed by guessing or discovering filenames.
- Sensitive contracts, invoices, payroll files, reports, or customer documents may be exposed.
- Logs may show normal authenticated access, making the bug harder to notice.
- The API leaks data because authorization is checked too late or not checked at all.

## Regression Test

### Test Name

User must not download another user's valid document.

### Given

User A is authenticated.

User A owns:

```txt
customer-a-contract.txt
```

User B owns:

```txt
customer-b-contract.txt
```

Both files exist in the document system.

Both filenames are valid and pass filename validation.

The documents table contains:

```txt
documents
---------
id | ownerUserId | fileName                | storagePath
1  | user_a      | customer-a-contract.txt | /safe/docs/a.txt
2  | user_b      | customer-b-contract.txt | /safe/docs/b.txt
```

### When

User A sends the following request:

```http
GET /api/documents/download?fileName=customer-b-contract.txt
Authorization: Bearer JWT_A
```

### Then

The API returns:

```http
404 Not Found
```

The API must not read or return the contents of:

```txt
customer-b-contract.txt
```

The response must not reveal whether User B's file exists.

The backend must check document ownership using the authenticated user identity before calling:

```js
fs.readFile(...)
```

Authentication only proves User A's identity. It does not prove User A is allowed to access User B's document.

## Secure Fix

The secure version must include the authenticated user's identity in the document lookup.

```js
import fs from "fs/promises";

app.get("/api/documents/download", authMiddleware, async (req, res) => {
  try {
    const fileName = req.query.fileName;

    if (typeof fileName !== "string") {
      return res.status(400).json({ error: "Invalid file name" });
    }

    if (!/^[a-zA-Z0-9_-]+\.txt$/.test(fileName)) {
      return res.status(400).json({ error: "Invalid file name" });
    }

    const document = await db.documents.findFirst({
      where: {
        fileName: fileName,
        ownerUserId: req.user.id,
      },
    });

    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    const fileContent = await fs.readFile(document.storagePath, "utf8");

    return res.type("text/plain").send(fileContent);
  } catch (err) {
    console.error("Document download failed:", err);
    return res.status(500).json({ error: "Could not download document" });
  }
});
```

## Why This Fix Is Safer

The insecure lookup was:

```js
where: {
  fileName: fileName,
}
```

That checks only the object identifier.

The secure lookup is:

```js
where: {
  fileName: fileName,
  ownerUserId: req.user.id,
}
```

This checks both:

```txt
Which document is being requested?
```

and:

```txt
Who is allowed to access it?
```

The key rule is:

```txt
Look up the object through the authenticated user's access boundary.
```

The API should not first fetch the document and then decide whether the user can access it.

It should fetch only documents the user is allowed to access.

## Why 404 Is Used

For private user-owned documents, returning `404 Not Found` is often safer than returning `403 Forbidden`.

If User A requests:

```txt
customer-b-contract.txt
```

a `403 Forbidden` response may reveal:

```txt
That file exists, but you cannot access it.
```

A `404 Not Found` response says:

```txt
No accessible document was found for this user.
```

This avoids leaking whether another user's document exists.

## Backend Security Rule

A valid identifier is not authorization.

For secure file download APIs:

- Authenticate the user.
- Validate the input shape.
- Look up the file through the authenticated user's access boundary.
- Do not trust `fileName` alone.
- Do not trust `userId` from the client.
- Use `req.user.id` from verified auth middleware.
- Do not call `fs.readFile()` until authorization has passed.
- Return `404` when the document does not exist for that user.

Authentication answers:

```txt
Who is the user?
```

Input validation answers:

```txt
Is the filename format acceptable?
```

Authorization answers:

```txt
Is this user allowed to read this exact document?
```

For secure file access, all three checks are required.
