# Malicious Mail Script Risk and Safe PoC

## Threat

Email content is attacker-controlled input.

If a mail client renders message body with unsafe HTML insertion such as `innerHTML` without escaping, a malicious sender may try to inject:
- JavaScript
- event handlers
- deceptive links
- style-based UI spoofing

## Safe PoC

An unsafe mail renderer might treat this message body as HTML:

```html
<img src="x" onerror="alert('mail-xss')">
```

If the client directly inserts that body into the page as trusted HTML, the `onerror` handler would run.

## Why The Current Browser UI Is Safer

The current web client renders message content through escaping rather than raw HTML insertion.

Relevant code:
- [web/app.js](../web/app.js)
- `escapeHtml(...)`

This means attacker-controlled message text is displayed as text, not executed as code.

## What Could Be Damaged In A Vulnerable Design

If a browser mail client were vulnerable, malicious mail could try to:
- steal session tokens
- issue forged mailbox actions
- change UI content to phish the user
- trick the user into unsafe clicks

## Current Residual Risk

The current implementation is safer than a naive HTML renderer, but mail content should still be treated as hostile input.

Important rules:
- never trust message body as HTML by default
- keep smart features advisory only
- continue escaping message text in the frontend
- avoid privileged automatic actions based on mail content
