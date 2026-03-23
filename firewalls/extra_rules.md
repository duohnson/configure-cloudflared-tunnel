# --- EXTRA RULES ---
Created by my.

# 1) Sensitive information / internal paths
What it does: blocks requests that try to access files or internal paths (configuration files, repos, admin panels).
Examples: "/.env", "/.git", "/etc/passwd", "/wp-admin"
```bash
(http.request.uri.path contains "..") or
(http.request.uri.path contains "/.env") or
(http.request.uri.path contains "/.git") or
(http.request.uri.path contains "/.svn") or
(http.request.uri.path contains "/.htaccess") or
(http.request.uri.path contains "/.htpasswd") or
(lower(http.request.uri.path) contains "/wp-admin") or
(lower(http.request.uri.path) contains "/wp-login") or
(lower(http.request.uri.path) contains "/wp-content") or
(lower(http.request.uri.path) contains "/wp-includes") or
(lower(http.request.uri.path) contains "xmlrpc.php") or
(lower(http.request.uri.path) contains "/phpmyadmin") or
(lower(http.request.uri.path) contains "/adminer") or
(lower(http.request.uri.path) contains "/wp-config") or
(lower(http.request.uri.path) contains "/etc/passwd") or
(lower(http.request.uri.path) contains "/proc/self") or
(lower(http.request.uri.path) contains "/cgi-bin/") or
```

# 2) Command execution / OS injection
What it does: detects attempts to execute system commands or use remote admin utilities.
Examples: "cmd.exe", "powershell", "system(...)"
```bash
(lower(http.request.uri.query) contains "cmd.exe") or
(lower(http.request.uri.query) contains "powershell") or
(lower(http.request.uri.query) contains "system(") or
(lower(http.request.uri.query) contains "system%28") or
(lower(http.request.uri.query) contains "exec(") or
(lower(http.request.uri.query) contains "exec%28") or
(lower(http.request.uri.query) contains "passthru(") or
(lower(http.request.uri.query) contains "passthru%28") or
(lower(http.request.uri.query) contains "shell_exec(") or
(lower(http.request.uri.query) contains "shell_exec%28") or
(lower(http.request.uri.query) contains "xp_cmdshell") or
(lower(http.request.uri.query) contains "load_file(") or
(lower(http.request.uri.query) contains "load_file%28") or
(lower(http.request.uri.query) contains "into%20outfile") or
(lower(http.request.uri.query) contains "into%20dumpfile") or
(lower(http.request.uri.query) contains "into+outfile") or
```

# 3) Cross-site scripting (XSS) and HTML/JS payloads
What it does: blocks parameters containing tags or attributes commonly used for XSS (script, img, iframe, onerror, document.cookie, etc.).
Examples: "<script>", "onerror=", "<iframe src=...>"
```bash
(lower(http.request.uri.query) contains "<script") or
(lower(http.request.uri.query) contains "%3cscript") or
(lower(http.request.uri.query) contains "</script") or
(lower(http.request.uri.query) contains "%3c/script") or
(lower(http.request.uri.query) contains "javascript:") or
(lower(http.request.uri.query) contains "javascript%3a") or
(lower(http.request.uri.query) contains "document.cookie") or
(lower(http.request.uri.query) contains "document.domain") or
(lower(http.request.uri.query) contains "document.write") or
(lower(http.request.uri.query) contains "window.location") or
(lower(http.request.uri.query) contains "string.fromcharcode(") or
(lower(http.request.uri.query) contains "string.fromcharcode%28") or
(lower(http.request.uri.query) contains "onerror=") or
(lower(http.request.uri.query) contains "onerror%3d") or
(lower(http.request.uri.query) contains "onload=") or
(lower(http.request.uri.query) contains "onload%3d") or
(lower(http.request.uri.query) contains "onmouseover=") or
(lower(http.request.uri.query) contains "onmouseover%3d") or
(lower(http.request.uri.query) contains "onfocus=") or
(lower(http.request.uri.query) contains "onfocus%3d") or
(lower(http.request.uri.query) contains "onclick=") or
(lower(http.request.uri.query) contains "onclick%3d") or
(lower(http.request.uri.query) contains "onsubmit=") or
(lower(http.request.uri.query) contains "onsubmit%3d") or
(lower(http.request.uri.query) contains "<img") or
(lower(http.request.uri.query) contains "%3cimg") or
(lower(http.request.uri.query) contains "<svg") or
(lower(http.request.uri.query) contains "%3csvg") or
(lower(http.request.uri.query) contains "<iframe") or
(lower(http.request.uri.query) contains "%3ciframe") or
(lower(http.request.uri.query) contains "<object") or
(lower(http.request.uri.query) contains "%3cobject") or
(lower(http.request.uri.query) contains "<embed") or
(lower(http.request.uri.query) contains "%3cembed") or
(lower(http.request.uri.query) contains "<body%20onload") or
(lower(http.request.uri.query) contains "<body+onload") or
(lower(http.request.uri.query) contains "alert(") or
(lower(http.request.uri.query) contains "alert%28") or
(lower(http.request.uri.query) contains "prompt(") or
(lower(http.request.uri.query) contains "prompt%28") or
(lower(http.request.uri.query) contains "confirm(") or
(lower(http.request.uri.query) contains "confirm%28") or
(lower(http.request.uri.query) contains "eval(") or
(lower(http.request.uri.query) contains "eval%28") or
(lower(http.request.uri.query) contains "settimeout(") or
(lower(http.request.uri.query) contains "setinterval(") or
(lower(http.request.uri.query) contains "<style") or
(lower(http.request.uri.query) contains "%3cstyle") or
(lower(http.request.uri.query) contains "expression(") or
(lower(http.request.uri.query) contains "<?php") or
(lower(http.request.uri.query) contains "%3c%3fphp") or
```

# 4) SQL injection and database enumeration
What it does: detects common SQLi patterns, functions and schema names that attempt to access sensitive data.
Examples: "union select", "or 1=1", "information_schema"
```bash
(lower(http.request.uri.query) contains "union%20select") or
(lower(http.request.uri.query) contains "union+select") or
(lower(http.request.uri.query) contains "union/**/select") or
(lower(http.request.uri.query) contains "union%20all%20select") or
(lower(http.request.uri.query) contains "union+all+select") or
(http.request.uri.query contains "')--") or
(http.request.uri.query contains "')/*") or
(http.request.uri.query contains "')%23") or
(http.request.uri.query contains "%27)--") or
(http.request.uri.query contains "%27)/*") or
(http.request.uri.query contains "%27)%23") or
(http.request.uri.query contains "%27%20or%20") or
(http.request.uri.query contains "%27+or+") or
(http.request.uri.query contains "%27%20OR%20") or
(http.request.uri.query contains "%27+OR+") or
(http.request.uri.query contains "%22%20or%20") or
(http.request.uri.query contains "%22%20OR%20") or
(lower(http.request.uri.query) contains "or%201%3d1") or
(lower(http.request.uri.query) contains "or+1%3d1") or
(lower(http.request.uri.query) contains "and%201%3d1") or
(lower(http.request.uri.query) contains "and+1%3d1") or
(lower(http.request.uri.query) contains "or%20%271%27%3d%271") or
(lower(http.request.uri.query) contains "waitfor%20delay") or
(lower(http.request.uri.query) contains "waitfor+delay") or
(lower(http.request.uri.query) contains "pg_sleep(") or
(lower(http.request.uri.query) contains "pg_sleep%28") or
(lower(http.request.uri.query) contains "benchmark(") or
(lower(http.request.uri.query) contains "benchmark%28") or
(lower(http.request.uri.query) contains "sleep(") or
(lower(http.request.uri.query) contains "sleep%28") or
(http.request.uri.query contains "'0:0:20'") or
(lower(http.request.uri.query) contains ";%20drop%20") or
(lower(http.request.uri.query) contains ";+drop+") or
(lower(http.request.uri.query) contains ";%20delete%20from") or
(lower(http.request.uri.query) contains ";%20insert%20into") or
(lower(http.request.uri.query) contains ";%20update%20") or
(lower(http.request.uri.query) contains ";%20select%20") or
(lower(http.request.uri.query) contains ";+select+") or
(lower(http.request.uri.query) contains "information_schema") or
(lower(http.request.uri.query) contains "pg_catalog") or
(lower(http.request.uri.query) contains "pg_tables") or
(lower(http.request.uri.query) contains "pg_shadow") or
(lower(http.request.uri.query) contains "pg_user") or
(lower(http.request.uri.query) contains "current_database(") or
(lower(http.request.uri.query) contains "current_database%28") or
(lower(http.request.uri.query) contains "current_user(") or
(lower(http.request.uri.query) contains "current_user%28") or
```

# 5) Functions and patterns used in attacks (concatenation, file loading, SQL functions)
What it does: detects use of functions commonly found in SQL/OS payloads.
Examples: "concat(", "load_file(", "into outfile"
```bash
(lower(http.request.uri.query) contains "concat(") or
(lower(http.request.uri.query) contains "concat%28") or
(lower(http.request.uri.query) contains "group_concat(") or
(lower(http.request.uri.query) contains "group_concat%28") or
(lower(http.request.uri.query) contains "string_agg(") or
(lower(http.request.uri.query) contains "string_agg%28") or
(lower(http.request.uri.query) contains "chr(") or
(lower(http.request.uri.query) contains "chr%28") or
(lower(http.request.uri.query) contains "md5(") or
(lower(http.request.uri.query) contains "md5%28") or
(lower(http.request.uri.query) contains "extractvalue(") or
(lower(http.request.uri.query) contains "updatexml(") or
```

# 6) Binary/hex patterns and null bytes
What it does: detects attempts to inject null bytes, long hex strings or hex-encoded payloads.
```bash
(http.request.uri.query contains "%00") or
(http.request.uri.query contains "0x00") or
(http.request.uri.query contains "0x3c62723e3c62723e3c62723e") or
(http.request.uri.query contains "0x3c696d67207372633d22") or
```

# 7) Additional manually created rules
# 7a) Block by User-Agent for scanning tools
What it does: detects known scanner/enum User-Agents.
```bash
(lower(http.request.headers["user-agent"][0]) contains "sqlmap") or
(lower(http.request.headers["user-agent"][0]) contains "masscan") or
(lower(http.request.headers["user-agent"][0]) contains "nikto") or
(lower(http.request.headers["user-agent"][0]) contains "acunetix") or
```

# 7b) Suspicious double extension (possible disguised webshell)
```bash
(http.request.uri.path contains ".php.") or
(http.request.uri.path contains ".php5") or
(http.request.uri.path contains ".phtml") or
```

# 7c) Long Base64-looking query (possible exfiltration or encoded payload)
Note: adjust threshold (200) according to legitimate traffic
```bash
(strlen(http.request.uri.query) > 200 and http.request.uri.query matches "(?i)^[A-Za-z0-9+/=]+$")
```