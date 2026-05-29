# Day 6 - Command Injection via Unsafe Shell Execution

## Vulnerable Pattern

The vulnerable endpoint accepts `reportName` from the query string and directly inserts it into a shell command.

```js
import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/api/reports/download", authMiddleware, (req, res) => {
  const reportName = req.query.reportName;

  if (!reportName) {
    return res.status(400).json({ error: "reportName is required" });
  }

  exec(`cat ./reports/${reportName}.txt`, (error, stdout, stderr) => {
    if (error) {
      console.error("Report download failed:", error);
      return res.status(500).json({ error: "Could not download report" });
    }

    return res.type("text/plain").send(stdout);
  });
});
```

The dangerous line is:

```js
exec(`cat ./reports/${reportName}.txt`);
```

`reportName` is user-controlled input. Since `exec()` runs the command through a shell, an attacker can inject shell metacharacters such as `;`, `&&`, `|`, `$()`, or backticks.

## Why This Is Vulnerable

A normal request may look like this:

```http
GET /api/reports/download?reportName=monthly-sales
Authorization: Bearer JWT_A
```

The server builds this command:

```bash
cat ./reports/monthly-sales.txt
```

But a malicious authenticated user can send:

```http
GET /api/reports/download?reportName=monthly-sales%3B%20echo%20hacked
Authorization: Bearer JWT_A
```

Decoded value:

```txt
monthly-sales; echo hacked
```

The server may build this shell command:

```bash
cat ./reports/monthly-sales; echo hacked.txt
```

Because `;` starts a second shell command, the attacker-controlled input is no longer just a report name. It becomes part of executable shell logic.

Authentication does not protect this endpoint. Authentication only proves who the user is. It does not make user input safe to pass into a shell command.

## Impact

If exploited, command injection can allow an attacker to:

- Execute unintended operating system commands.
- Read sensitive files.
- Exfiltrate secrets or environment variables.
- Modify or delete files.
- Pivot further inside the server environment.
- Turn a normal API endpoint into a remote command execution risk.

There is also a related path traversal risk if user input is directly used in file paths. For example:

```txt
../../private/secrets
```

But the larger issue in this endpoint is command injection because the input is passed into `exec()`.

## Regression Test

### Test Name

Malicious `reportName` must not execute shell commands.

### Given

User A is authenticated.

User A is allowed to use:

```http
GET /api/reports/download
```

The endpoint accepts a `reportName` query parameter.

Only safe report names should be accepted, such as:

```txt
monthly-sales
q1_finance
report-2025
```

Report names must only contain:

```txt
letters
numbers
underscore
hyphen
```

The client must not be allowed to provide path separators, dots, spaces, semicolons, shell operators, or file extensions.

### When

User A sends the following malicious request:

```http
GET /api/reports/download?reportName=monthly-sales%3B%20echo%20hacked
Authorization: Bearer JWT_A
```

Decoded malicious input:

```txt
monthly-sales; echo hacked
```

### Then

The API returns:

```http
400 Bad Request
```

The API does not execute:

```bash
echo hacked
```

The response body must not contain:

```txt
hacked
```

The server must not run any shell command using the user-controlled `reportName`.

Authentication only proves User A's identity. It does not make `reportName` safe to pass into a shell command.

## Secure Fix

Do not use `exec()` for reading files. The API should validate the logical report name, build the file path safely on the server, and read the file using Node's filesystem APIs.

```js
import path from "path";
import fs from "fs/promises";

const REPORTS_DIR = path.resolve(process.cwd(), "reports");

app.get("/api/reports/download", authMiddleware, async (req, res) => {
  try {
    const reportName = req.query.reportName;

    if (typeof reportName !== "string") {
      return res.status(400).json({ error: "Invalid report name" });
    }

    const isValidReportName = /^[a-zA-Z0-9_-]+$/.test(reportName);

    if (!isValidReportName) {
      return res.status(400).json({ error: "Invalid report name" });
    }

    const reportPath = path.resolve(REPORTS_DIR, `${reportName}.txt`);

    if (!reportPath.startsWith(REPORTS_DIR + path.sep)) {
      return res.status(400).json({ error: "Invalid report name" });
    }

    let fileContent;

    try {
      fileContent = await fs.readFile(reportPath, "utf8");
    } catch (err) {
      if (err.code === "ENOENT") {
        return res.status(404).json({ error: "Report not found" });
      }

      console.error("Unexpected report read error:", err);
      return res.status(500).json({ error: "Could not download report" });
    }

    return res.type("text/plain").send(fileContent);
  } catch (err) {
    console.error("Unexpected report endpoint error:", err);
    return res.status(500).json({ error: "Could not download report" });
  }
});
```

## Why This Fix Is Safer

The secure version avoids the vulnerable pattern completely.

Instead of this:

```js
exec(`cat ./reports/${reportName}.txt`);
```

It uses:

```js
fs.readFile(reportPath, "utf8");
```

This avoids shell execution entirely.

The allowlist regex:

```js
/^[a-zA-Z0-9_-]+$/
```

allows only simple report names.

It rejects dangerous input such as:

```txt
../secret
monthly-sales; echo hacked
monthly-sales && whoami
monthly-sales | cat /etc/passwd
monthly-sales.txt
```

The server adds `.txt` itself:

```js
`${reportName}.txt`
```

So the client cannot choose the file extension.

The resolved path check ensures the final file path remains inside the intended reports directory:

```js
reportPath.startsWith(REPORTS_DIR + path.sep)
```

This prevents unsafe prefix matches such as:

```txt
/app/reports-backup/payroll.txt
```

from being treated as if they were inside:

```txt
/app/reports
```

## Backend Security Rule

Never pass user-controlled input into shell commands.

For backend APIs:

- Use allowlists instead of trying to block dangerous characters one by one.
- Reject invalid input instead of stripping or modifying it.
- Do not trust authenticated users to provide safe input.
- Avoid shell execution when a safer language/library API exists.
- For file access, validate the logical identifier and let the server construct the real file path.
- For path safety, resolve the final path and confirm it stays inside the expected directory.

Authentication answers:

```txt
Who is the user?
```

Authorization answers:

```txt
What is the user allowed to access?
```

Input validation answers:

```txt
Is this input safe and expected for this operation?
```

For this endpoint, all three matter.