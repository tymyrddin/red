# The browser as attack surface

The browser is where most sensitive work now happens. Email, documents, financial systems, HR platforms, code repositories, and cloud consoles all run in browser tabs. The operating system beneath may be fully patched and EDR-monitored; the browser is a separate execution environment with its own attack surface, its own extension ecosystem, and its own storage that sits largely outside the OS-level security model.

## Session storage and cookies

The browser maintains authentication state through cookies and tokens stored in session storage and local storage. These persist across tabs and, for persistent cookies, across restarts. A user who authenticates to their corporate SSO in the morning creates tokens that may remain valid for eight or more hours without re-authentication prompts.

From the browser's perspective, these tokens are accessible to any script running in the same origin. Cross-site scripting attacks that execute JavaScript in a victim's browser can exfiltrate cookies (where the `HttpOnly` flag is absent) and tokens from storage. From an attacker-controlled extension, this limitation disappears: extensions run with access to all origins simultaneously.

## Malicious browser extensions

Browser extensions are installed at the user level and run with elevated trust compared to web page content. They can read and modify the content of any tab, intercept and modify HTTP requests and responses, access cookies across all domains, inject JavaScript into pages, and communicate with external servers. The permission model requires user consent at install time, but consent dialogs are accepted without scrutiny in most cases.

Extension-based attacks have followed two main paths: malicious extensions published to the Chrome Web Store or Firefox Add-ons under benign-sounding names that deliver credential harvesting functionality, and compromised legitimate extensions where an attacker gains access to the extension developer's account and pushes a malicious update to the extension's existing user base. The second path is particularly dangerous because existing users receive the update automatically without any new permission prompts.

A malicious extension with broad permissions can exfiltrate all session cookies, modify the content of banking and SaaS pages to harvest credentials as they are typed, intercept OAuth flows to capture access tokens before they reach the application, and maintain persistent access to the user's authenticated sessions.

## In-browser exploitation and sandbox escapes

Browser exploitation chains typically begin with a JavaScript vulnerability that achieves arbitrary code execution within the renderer process's sandbox, followed by a sandbox escape to reach the OS. The sandbox escape is the harder component and is what limits the practical impact of most browser vulnerabilities.

Without a sandbox escape, an attacker with JavaScript execution is confined to the browser's origin model but can still: steal tokens and cookies, read clipboard contents, capture screenshots of browser tabs, access files the user uploads, and make authenticated requests to any service the user is logged into via `fetch()` or `XMLHttpRequest`. These capabilities are often sufficient to achieve the objectives of a targeted attack without requiring a full OS compromise.

## Debugging interface abuse

Browser developer tools expose an inspection and debugging interface that can be accessed remotely if the browser is launched with the `--remote-debugging-port` flag. Automation tools such as Selenium and Playwright use this interface legitimately. An attacker with access to a process on the same host can connect to an exposed debugging port, read all tab content, inject JavaScript, extract cookies, and navigate to arbitrary pages within the victim's authenticated sessions. Electron applications embed Chromium and frequently expose debugging interfaces for troubleshooting, sometimes in production builds.

## Cross-origin information leaks

Same-origin policy prevents scripts on one origin from reading responses from another. But several side channels leak cross-origin information: timing attacks on cached resources reveal whether a resource was recently visited; cross-origin resource inclusion can leak portions of responses through error messages; XS-Leaks (cross-site leaks) is a research area documenting dozens of browser behaviours that leak information about cross-origin state without violating the letter of the same-origin policy.

Spectre-class vulnerabilities in speculative execution are relevant in browser contexts because browsers expose high-resolution timers (through `SharedArrayBuffer` and other mechanisms) that make timing side-channel attacks practical. These have been partially mitigated through site isolation and reduced timer precision, but the mitigations are incomplete and the attack surface continues to evolve.
