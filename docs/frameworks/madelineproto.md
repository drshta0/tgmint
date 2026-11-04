# MadelineProto (PHP)

You use the `tgmint` CLI to make the identity, then pass it to
MadelineProto's settings.

```bash
pip install tgmint
composer require danog/madelineproto
tgmint mint --preset android --unique-id me --save me.fingerprint.json
```

## Connect

```php
<?php
require 'vendor/autoload.php';

use danog\MadelineProto\API;
use danog\MadelineProto\Settings;
use danog\MadelineProto\Settings\AppInfo;

$fp = json_decode(file_get_contents('me.fingerprint.json'), true);

$app = (new AppInfo)
    ->setApiId($fp['api_id'])
    ->setApiHash($fp['api_hash'])
    ->setDeviceModel($fp['device_model'])
    ->setSystemVersion($fp['system_version'])
    ->setAppVersion($fp['app_version'])
    ->setLangCode($fp['lang_code'])
    ->setLangPack($fp['lang_pack']);

$settings = (new Settings)->setAppInfo($app);

$MadelineProto = new API('me.madeline', $settings);
$MadelineProto->start();
print_r($MadelineProto->getSelf());
```

## Bring a session from another library

MadelineProto 8 can import Telethon and Pyrogram session files. Convert to
one of those first, then import:

```bash
tgmint convert --from ./tdata --from-format tdata \
               --to me.session --to-format telethon-session
```

```php
$MadelineProto = API::fromTelethon('me.session', 'me.madeline', $settings);
```

Check [MadelineProto's login docs](https://docs.madelineproto.xyz/docs/LOGIN.html)
for the import API in your version.
