# Getting a session out of the official Android app

The user story: *"I'm logged into Telegram on my phone; I want that account in
Telethon / kurigram / GramJS / tdata without a new login."*

This page documents what is actually possible, what is not, and the exact steps for
each working path. Everything here is for **your own device and your own account**.

> Status note: `--from-format android-dir` **is shipped** — see
> [Using the dump with tgmint](#using-the-dump-with-tgmint) below. The file
> formats and the recipes were verified first; the reader followed them.
> QR login is `tgmint login-qr`.

## What is on the phone

The official Android app stores, per account, one config file:

| Path | Contents |
|---|---|
| `files/tgnet.dat` (account 0) | the `tgnet` config: current DC id, per-DC addresses, and the 256-byte MTProto auth key, **unencrypted** |
| `files/account<N>/tgnet.dat` (accounts 1+) | same, per account |
| `files/account<N>/dc<ID>conf.dat` | per-DC mirror of the same struct |
| `shared_prefs/userconfing.xml` (account 0) | user id as a Base64 Telegram `User` object |
| `shared_prefs/userconfig<N>.xml` (accounts 1+) | same, per account |

The app's own "local passcode" is only a screen-lock check (`passcodeHash1` +
`passcodeSalt`); it does **not** encrypt `tgnet.dat`. Protection is the Android
sandbox: app UID, SELinux and file-based encryption. Reading the file therefore means
reading it as the app's UID, i.e. root or an equivalent.

`tgnet.dat` is a 4-byte length-prefixed stream: `configVersion 5`, test/blocked flags,
last system language code, current DC id, session ids, then one stream per datacenter
(`version 13`: dc id, `lastInitVersion` = the app's versionCode, addresses, auth keys,
salts). The `lastInitVersion` and the language code are the device identity the app
actually used, which is why an import can carry a coherent fingerprint.

## Path 1: Android emulator or container (recommended, no physical root)

Log into Telegram inside a rooted Android container, then pull the files.

AVD:

```sh
# 1. create an AVD (API 34, image with Google APIs), boot it, then:
adb root
adb install telegram.apk            # from telegram.org/android
# 2. log in inside the emulator (SMS code or 2FA, as usual),
#    then stop the app so tgnet.dat is flushed:
adb shell am force-stop org.telegram.messenger
# 3. pull the credential material:
adb pull /data/data/org.telegram.messenger/files/tgnet.dat /tmp/tgnet.dat
adb pull /data/data/org.telegram.messenger/shared_prefs/userconfing.xml /tmp/
#    for a second account: files/account1/tgnet.dat and shared_prefs/userconfig1.xml
```

Waydroid (Linux): `sudo waydroid shell` is root; copy the same two files out.
redroid (Docker): `docker run --privileged redroid/redroid`, `adb connect …`,
`adb root`, then the same `adb pull`s. Telegram does not need Play Services to log in
(push notifications are separate), so a GMS-less image is fine.

Then see [Using the dump with tgmint](#using-the-dump-with-tgmint) below.

Cost: one login (SMS/2FA) inside the container; no bootloader unlock, no root on your
daily phone. This is the same "log in once, use it anywhere" trade the QR path makes.

## Using the dump with tgmint

`--from-format android-dir` is shipped. Point `tgmint convert` at the
dump directory — the whole app data dir (what the `adb pull`s above
produce), the `files/` directory alone, or a flat folder holding a
pulled `tgnet.dat` and prefs XML side by side all work:

```sh
tgmint convert --from /tmp/android-dump --from-format android-dir \
    --to out.session --to-format telethon-session
```

What the reader does:

* reads `tgnet.dat` (falling back to `tgnet.dat.bak`, exactly like the
  app's own crash recovery) and takes the **current DC's** permanent
  auth key, DC id and first endpoint — no crypto is involved anywhere;
* reads the account's user id from `userconfing.xml` /
  `userconfig<N>.xml` best-effort: an unreadable or future-format pref
  never fails the import, the id just comes out unset;
* writes any destination of the matrix (Telethon, Pyrogram-family,
  GramJS, tdata; or seal a `.tgmint` envelope via `tgmint profile seal`
  afterwards). Pyrogram-family outputs carry the official app's own
  `api_id` (4 today) as provenance — recorded in the conversion report —
  instead of the 2040 placeholder;
* one account at a time: `--account-index N` picks slot N (account 0 is
  the app's first account; accounts 1+ live in `files/account<N>/`).
  There is deliberately no "convert all".

Converting from a *forked* client's dump (not the official app)? Call
`convert_session(..., api_id=<the fork's id>)` from Python so the
destination records the right provenance.

## Path 2: own phone with an unlocked bootloader (root)

This is the only way to read the *existing* phone's session rather than creating a new
one. Unlocking the bootloader wipes userdata, so it ends in a re-login anyway:

```sh
# after Magisk/root, on the phone (or adb shell su):
su -c 'am force-stop org.telegram.messenger'
adb pull /data/data/org.telegram.messenger/files/tgnet.dat /tmp/tgnet.dat
adb pull /data/data/org.telegram.messenger/shared_prefs/userconfing.xml /tmp/
```

## Path 3: QR login (no file access at all)

tgmint shows `tg://login?token=…`, you open Telegram on the phone and confirm it
(Settings → Devices → Scan QR / "Link Desktop Device"), and the new session is
authorized directly. No code entry, no root, no files: `tgmint login-qr`
(Telegram's flow is `auth.exportLoginToken` plus `updateLoginToken`).

This is a *new* session rather than a copy of the phone's key, so the phone's own
session stays logged in and untouched.

## Path 4: self-built Telegram on the phone

If you build the app yourself (the official source is public), make your build
`android:debuggable="true"` or declare `android:fullBackupOnly="true"`. Then either
`adb exec-out run-as org.telegram.messenger cat files/tgnet.dat` or a real
`adb backup` works. Only worth it if you want the *existing* session on an unrooted
phone and are comfortable with the SDK/NDK build.

## Path 5: device-to-device transfer (niche)

Android's Setup Wizard "copy apps & data" moves app data between phones even when the
app has a backup agent (`IGNORE_ALLOW_BACKUP_IN_D2D`). The receiving phone then holds
`tgnet.dat` — but you still need root on the receiver to read it. Two devices, one of
them rooted; docs only.

## Dead ends (verified, do not spend time here)

* **`adb backup` cannot work for the official app.** Two independent reasons:
  (a) Telegram declares `backupAgent=".BackupAgent"` without `fullBackupOnly`, so
  `BackupEligibilityRules.appGetsFullBackup()` returns false and the app is routed to
  key-value backup — the `.ab` includes only the `saved_tokens` prefs;
  (b) since Android 12, `RESTRICT_ADB_BACKUP` (compat change 171032338) restricts
  adb-backup eligibility for targetSdk ≥ 31 apps to debuggable builds, which the
  official app is not.
* **EDL / MTK / chip-off dumps** end in file-based-encryption ciphertext (the CE keys
  are wrapped by the TEE keymaster) and bootloader unlock wipes the data first.
* **App-side "export session" does not exist** in the official app, Forkgram or
  Telegram X. Nagram (and NekoX-family forks) ship *QR login* and *QR confirm*, not a
  session export.
* **No older Telegram APK escapes the gate either.** `allowBackup` was `false`
  until 9.4.0 (2023-02), and that same commit flipped it to `true` *and* added
  `backupAgent=".BackupAgent"` — verified from the official history
  (`git show 135e3cc76 -- TMessagesProj/src/main/AndroidManifest.xml`). There is
  therefore no official version that is both backup-eligible and agent-free, so
  "downgrade to an old APK, then `adb backup`" does not work.
* **Third-party stealer/malware tooling** is out of scope by this project's guardrails.

## What tgmint ships

* The `--from-format android-dir DIR` reader for `tgnet.dat` +
  `userconfig*.xml` (`tgmint.codec.android`), cross-checked against the
  official client source and AndroidTelePorter.
* `tgmint login-qr` as the no-file-access path (see [QR login](qr-login.md)).
* Not supported: `.ab` backups from self-built or patched builds.
