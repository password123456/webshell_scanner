# webshell_scanner

Overview:
- ASP, PHP, JSP Webshell detection based on patterns.
- You can add, remove, modify patterns.
- Addtional features, this can detect file written from chinese words.

Expects:
 - I hope this helps when an incident response.

```sh
usage: quick_scan_webshell_release_final.py [-h] [-p] scan_path

::::: Quick WebShell-Scan + Scan Chinese Words :::::

positional arguments:
  scan_path   ex) /var/www/html/upload

optional arguments:
  -h, --help  show this help message and exit
  -p, --path  ex) python quick_scan_webshell_v0.1.py -p /var/www/html/upload
```

Detect e.g:
```sh
======================================================================
 + File         : /var/www/html/webshll/webshell-master/jsp/hackk8/JSP_66/other/jspspy_k8.jsp
 + File Owner   : 0:0
 + Permission   : 644
 + Last accessed: Mon Jul 20 14:44:56 2015
 + Last modified: Mon Jul 20 12:42:20 2015
 + Filesize     : 82 KB
 + MD5          : 71097537a91fac6b01f46f66ee2d7749
 + SHA1         : d51d367159c1a4f72ea64f0c2d160c8204cdf29e
 + SHA256       : 9ce81cfc056822ec9962aa8d6ca2233ac56e26a10f96cddc117d89b73a14c060


 [*] PHP Suspicious function used: [count / 82 ]
 [*] ASP Suspicious function used: [count / 8 ]
 [*] JSP Suspicious function used: [count / 3 ]
 ```
