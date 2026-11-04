# Fingerprint & sidecar

A `Fingerprint` is the frozen, serializable identity an account presents
(device model, system and app version, language, timezone). Mint it once,
save it next to the session as a sidecar, and reload it from then on, so the
account keeps the identity it was born with.

::: tgmint.fingerprint.Fingerprint

::: tgmint.sidecar

::: tgmint.audit
