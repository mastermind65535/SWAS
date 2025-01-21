# S.W.A.S. (SECURE WEB AUTHENTICATION SYSTEM)
S.W.A.S. uses SQL prepared statement, preventing SQLi, or SQL injection attacks against cyber attacks.
Hashed passwords are created with the following mechanism: SHA-256 Hash Algorithm + Random Salt.

## Disclaimer
> The creator(s) of this software assume no liability and are not responsible for any misuse or damages arising from the use of this software.


## Tip
### Create a rate limit system
> ```php
> $__MAX_LOGIN_ATTEMPT = 3;       // Maximum 3 login attempts
> ```
> 
> ```sql
> INSERT INTO users (id, pwd, salt, login_attempt) VALUES (?, ?, ?, ?)
> ```
> 
> ```php
> if ((int)$row["login_attempt"] > $__MAX_LOGIN_ATTEMPT) { return false; }
> ```

### Give a delay after one login attempt.
> ```php
> sleep(3);        // PHP second unit delay: 3s
> ```
> 
> ```php
> usleep(3000000); // PHP micro-second unit delay: 3s (3,000,000)
> ```
