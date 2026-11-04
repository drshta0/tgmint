# Profile envelope & heal

A `.tgmint` profile bundles a session, the fingerprint it was born with
and the passkey that can recover it. It can optionally be sealed with a
passphrase (AES-256-GCM, PBKDF2-SHA256). `heal` uses the bundled passkey
to sign a dead session back in.

::: tgmint.profile

::: tgmint.heal
