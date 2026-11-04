# TDLib

TDLib takes the identity in its `setTdlibParameters` call. Every TDLib
wrapper (aiotdlib, python-telegram, tdl for Node, etc.) passes these fields
through in some form.

```bash
tgmint mint --preset android --unique-id me --save me.fingerprint.json
```

Example with TDLib's JSON interface:

```python
import json

fp = json.load(open("me.fingerprint.json"))

set_params = {
    "@type": "setTdlibParameters",
    "api_id": fp["api_id"],
    "api_hash": fp["api_hash"],
    "device_model": fp["device_model"],
    "system_version": fp["system_version"],
    "application_version": fp["app_version"],
    "system_language_code": fp["system_lang_code"],
    "database_directory": "tdlib-db",
    "use_message_database": True,
}
# td_send(client, json.dumps(set_params).encode())
```

Note that TDLib calls it `application_version`, not `app_version`.

## Limits

- TDLib stores sessions in its own database. tgmint can't convert sessions
  to or from it.
- tgmint's passkey and QR login talk to Telegram directly, so they can't
  run inside TDLib. TDLib has its own QR login
  (`requestQrCodeAuthentication`).
