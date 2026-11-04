# Contributing to tgmint

Thanks for considering a contribution. tgmint is a single-account Telegram
identity toolkit (a fork of [thedemons/opentele](https://github.com/thedemons/opentele)).
Read these ground rules first — they are enforced in review.

## Ground rules (the short version)

1. **Own-account tooling only.** tgmint converts and repairs *your own*
   sessions. PRs that add batch mode, multi-account management, account
   farming, or anything that scales abuse will be closed without merge.
2. **Tests are offline and deterministic.** Never make a live network call
   from a test. Network-dependent behavior is captured as recorded/golden
   fixtures — see `tests/` for the existing patterns and follow them.
3. **Every data value must cite its source.** Versions, api_ids, device
   pools, TL layers: each carries the URL it was verified against (as a
   comment next to the value). A data value without a verifiable source
   gets deleted, not merged.
4. **You wrote the code you submit** (DCO-style). By submitting a PR you
   certify that the contribution is yours — or properly attributed fork
   lineage — and that you have the right to license it under the repo's
   MIT license. `git commit -s` and `Signed-off-by` trailers are
   appreciated and respected.

## Dev setup

Python ≥ 3.9. Runtime dependencies are `telethon` + `tgcrypto` only.

```bash
git clone https://github.com/drshta0/tgmint
cd tgmint
python3 -m venv .venv
.venv/bin/pip install -e ".[passkeys]" pytest ruff
```

Extras: `[passkeys]` adds `cryptography` (passkey create/sign);
`[qt]` adds PyQt5 only as a tdata fallback (`TGMINT_TDATA_QT=1`) and to
run the oracle-equivalence tests.

## Running the checks

```bash
.venv/bin/python -m pytest -q                        # full suite, must stay green
.venv/bin/python selfcheck.py                        # must print "all pools fresh"
.venv/bin/ruff check src tests --select E9,F63,F7    # CI smoke lint
```

- `selfcheck.py` fails if any stale 2022-era client version leaks from
  the device pools. If you touch version or pool data, refresh it from
  the live source and cite the verifying URL in the PR.
- The suite is seeded deterministically (by auth_key) and never contacts
  Telegram. If your change involves network behavior, record a fixture
  and test against the recording.

## What makes a good PR

- Small and single-purpose; describe what and why.
- New behavior comes with offline tests.
- New data values come with source URLs next to the value.
- No new hard runtime dependencies; optional features go behind extras.
- User-visible changes update `docs/` and add a `CHANGELOG.md` entry
  under `## [Unreleased]`.
- Don't claim the project is "first" at anything unless you've checked.

## Licensing

MIT (see [LICENSE](LICENSE)), continuing the opentele lineage. Unless you
state otherwise, contributions are licensed MIT by default.

## Reporting a security issue

Use GitHub private vulnerability reporting on this repository. Do not
open a public issue for security problems.
