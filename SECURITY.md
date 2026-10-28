# Security Policy

## Scope

tgmint reads and writes the files that *are* a Telegram account's credentials:
Telethon/Pyrogram **session files**, Telegram Desktop **tdata folders**, and
the **passkey files** minted by `tgmint.passkeys`. All of these are bearer
tokens — anyone who obtains a copy can use the account. Please report anything
that could leak these files or their contents, weaken their protection at rest
(for example: writing secrets with weak or reused keys, world-readable
permissions, or secret material left in temporary locations), or let a
crafted session/tdata/passkey file execute code or crash the parser when tgmint
opens it. Bugs that only affect accounts you do not control are out of scope —
this library is for accounts you own.

## Supported Versions

Only the **latest release** receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest release on PyPI | ✅ |
| anything older        | ❌ |
| upstream opentele     | ❌ (not maintained here) |

## Reporting a Vulnerability

**Do not open a public issue for a vulnerability.** Instead, use GitHub's
private vulnerability reporting:

> https://github.com/drshta0/tgmint/security/advisories/new

Please include how to reproduce the issue, what input triggers it, and which
file type it concerns (session / tdata / passkey). If you already have a fix,
mention it — coordinated disclosure is welcome.

There is no formal SLA, but we aim to **acknowledge reports within 14 days**.
Please do not disclose the issue publicly before a fix is released.

## Handling credential files safely

- **Never commit session, tdata, or passkey files to a repository** (including
  in issues, pull requests, and test fixtures) — treat every one of those
  files as if it were a password, because it is one.
- Prefer keeping them in an encrypted store, and revoke/terminate any session
  whose file may have been copied before investigating.
- When sharing a reproducer for a bug, generate a throwaway or synthetic file
  rather than reusing a real one.
