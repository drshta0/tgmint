# GramJS (Node.js)

GramJS can't import a Python library, so you use the `tgmint` CLI to make
the identity and the session, then read both from Node.

```bash
pip install tgmint
npm install telegram
```

## 1. Make an identity

```bash
tgmint mint --preset desktop --unique-id me --save me.fingerprint.json
```

`me.fingerprint.json` looks like this (trimmed):

```json
{
  "api_id": 2040,
  "api_hash": "b18441a1ff607e10a989891a5462e627",
  "app_version": "7.3.3",
  "device_model": "Dell DXC061",
  "lang_code": "en",
  "lang_pack": "tdesktop",
  "system_lang_code": "en-US",
  "system_version": "Linux MATE Wayland glibc 2.39",
  "tz_zone": "America/New_York"
}
```

## 2. Get a session (optional)

Skip this to log in from scratch with a phone number. Otherwise convert an
existing one:

```bash
# from Telegram Desktop
tgmint convert --from ./tdata --from-format tdata --to me.gramjs --to-format gramjs-string

# or log in by QR / passkey and get a GramJS string directly
tgmint login-qr --preset desktop --to me.gramjs --to-format gramjs-string
```

## 3. Connect

```js
const fs = require("fs");
const { TelegramClient } = require("telegram");
const { StringSession } = require("telegram/sessions");
const input = require("input"); // npm install input

const fp = JSON.parse(fs.readFileSync("me.fingerprint.json", "utf8"));
const saved = fs.existsSync("me.gramjs") ? fs.readFileSync("me.gramjs", "utf8").trim() : "";

const client = new TelegramClient(new StringSession(saved), fp.api_id, fp.api_hash, {
  deviceModel: fp.device_model,
  systemVersion: fp.system_version,
  appVersion: fp.app_version,
  langCode: fp.lang_code,
  systemLangCode: fp.system_lang_code,
});

(async () => {
  await client.start({
    phoneNumber: () => input.text("Phone: "),
    phoneCode: () => input.text("Code: "),
    password: () => input.text("2FA password: "),
    onError: console.error,
  });
  fs.writeFileSync("me.gramjs", client.session.save(), { mode: 0o600 });
  console.log(await client.getMe());
})();
```

GramJS has no `lang_pack` option, so that field stays at the library
default.
