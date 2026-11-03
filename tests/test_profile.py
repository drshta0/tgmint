"""Offline tests for tgmint.profile — the portable identity envelope (.tgmint).

What is pinned here:

* plaintext and sealed round trips, including the passkey and whatever
  extra keys a caller hangs on the fingerprint dict;
* the file discipline: JSON, mode 0600, atomic, and an existing path is
  never overwritten;
* what a sealed file must and must not contain, and that the seal is
  randomized (fresh salt + nonce per call);
* every read-side failure lands in ONE exception type
  (:class:`tgmint.profile.ProfileError`): wrong passphrase, tampered
  ciphertext, tampered salt/nonce, unknown KDF, implausible iteration
  count, missing crypto, and cross-validation mismatches;
* the codec integration: ``convert_session(..., source_format="profile")``,
  ``read_session`` and the ``.tgmint`` suffix inference.

Every test is offline; the sealed ones pay for real PBKDF2 (600000
iterations) exactly like production does — that is the cost of testing the
real KDF instead of a stub.
"""

import base64
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from tgmint import codec
from tgmint.codec import gramjs, pyrogram, telethon
from tgmint.codec.data import SessionData
from tgmint.fingerprint import Fingerprint
from tgmint.profile import (
    FORMAT,
    ITERATIONS,
    KDF,
    OpenedProfile,
    ProfileError,
    SESSION_FORMATS,
    guess_format,
    inspect_profile,
    open_profile,
    read_profile,
    seal,
    write_profile,
)

def no_crypto():
    """Context manager that makes `import cryptography...` fail.

    Simulates a build without the `passkeys` extra (the import hook is the
    honest way: `cryptography` is installed here, so patching sys.modules
    alone leaves its already-imported submodules reachable).
    """
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError(f"No module named {name!r} (simulated)")
        return real_import(name, *args, **kwargs)

    return mock.patch("builtins.__import__", blocked)

KEY = os.urandom(256)
OTHER_KEY = os.urandom(256)
USER_ID = 777000
API_ID = 2040
DC_ID = 2

try:  # the seal needs the `passkeys` extra; everything else must not
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment without cryptography
    HAVE_CRYPTO = False


def session(**overrides):
    fields = dict(dc_id=DC_ID, auth_key=KEY, user_id=USER_ID, api_id=API_ID)
    fields.update(overrides)
    return SessionData(**fields)


def fingerprint(**overrides):
    """A coherent desktop fingerprint without minting randomness."""
    data = dict(
        api_id=2049,
        api_hash="0123456789abcdef0123456789abcdef",
        device_model="Desktop",
        system_version="Windows 10",
        app_version="5.4.1 x64",
        lang_code="en",
        system_lang_code="en-US",
        lang_pack="tdesktop",
        tz_zone=None,
        origin="tdesktop",
        schema_version=1,
    )
    data.update(overrides)
    return Fingerprint(**data)


def fingerprint_data(**overrides):
    """A fingerprint dict as it appears in a container, plus the optional
    ``user_id``/``dc_id`` extras the cross-validation reads."""
    data = fingerprint().to_dict()
    data.update(overrides)
    return data


def passkey_store(user_id=USER_ID, dc_id=DC_ID, **overrides):
    """The shape PasskeyStore.to_dict() writes (a fake, no real key material)."""
    data = {
        "version": 1,
        "credential_id": base64.urlsafe_b64encode(b"cred-1").decode().rstrip("="),
        "rp_id": "telegram.org",
        "origin": "https://telegram.org",
        "alg": -7,
        "user_handle": f"{dc_id}:{user_id}",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        "sign_count": 3,
        "created_at": "2026-10-31T12:00:00+00:00",
        "telegram_passkey_id": "pk-1",
        "name": "tgmint software passkey",
    }
    data.update(overrides)
    return data


#: session-format label -> the codec writer whose string that label stores
_WRITERS = {
    "telethon-string": telethon.write_string,
    "telethon-session": telethon.write_string,
    "pyrogram-string": pyrogram.write_string,
    "pyrogram-session": pyrogram.write_string,
    "gramjs-string": gramjs.write_string,
}


def broken_container(session_data, session_format, *, fingerprint=None, passkey=None):
    """Assemble a container by hand, exactly in the shape ``seal()`` writes.

    The negative cross-validation cases need parts that disagree with each
    other; ``seal()`` refuses those (it must never publish an envelope
    ``open_profile`` rejects), so the broken container is built here
    instead — same JSON tree, no validation.
    """
    return {
        "format": FORMAT,
        "session": {
            "format": session_format,
            "encoding": "utf8",
            "data": _WRITERS[session_format](session_data),
        },
        "fingerprint": fingerprint,
        "passkey": passkey,
        "meta": {
            "created": "2026-11-01T00:00:00+00:00",
            "tgmint": "test",
            "note": "",
        },
    }


class PlainRoundTrip(unittest.TestCase):
    def test_round_trip_keeps_every_part(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "acct.tgmint")
        container = seal(
            session(),
            "telethon-string",
            fingerprint=fingerprint(),
            passkey=passkey_store(),
            note="primary account",
        )
        self.assertNotIn("sealed", container)
        write_profile(container, path)

        opened = open_profile(path)
        self.assertIsInstance(opened, OpenedProfile)
        self.assertEqual(opened.session.dc_id, DC_ID)
        self.assertEqual(opened.session.auth_key, KEY)
        self.assertEqual(opened.session_format, "telethon-string")
        self.assertFalse(opened.sealed)
        self.assertEqual(opened.fingerprint, fingerprint())
        self.assertEqual(opened.passkey, passkey_store())
        self.assertEqual(opened.meta["note"], "primary account")
        self.assertTrue(opened.meta["created"])
        self.assertTrue(opened.meta["tgmint"])
        self.assertEqual(opened.path, path)

    def test_file_is_json_and_private(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "acct.tgmint")
        write_profile(seal(session(), "telethon-string"), path)
        with open(path, encoding="utf-8") as fp:
            raw = json.load(fp)
        self.assertEqual(raw["format"], FORMAT)
        self.assertEqual(raw["session"]["encoding"], "utf8")
        self.assertEqual(
            sorted(raw), ["fingerprint", "format", "meta", "passkey", "session"]
        )
        self.assertIsNone(raw["fingerprint"])
        self.assertIsNone(raw["passkey"])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_write_refuses_to_overwrite(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "acct.tgmint")
        write_profile(seal(session(), "telethon-string"), path)
        with open(path, "rb") as fp:
            before = fp.read()
        with self.assertRaises(FileExistsError):
            write_profile(seal(session(auth_key=OTHER_KEY), "telethon-string"), path)
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), before)

    def test_write_rejects_a_non_container(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "acct.tgmint")
        for bad in ({}, {"format": "nope"}, {"format": FORMAT}):
            with self.subTest(bad=bad):
                with self.assertRaises(ProfileError):
                    write_profile(bad, path)
        self.assertFalse(os.path.exists(path))

    def test_open_from_dict(self):
        container = seal(session(), "pyrogram-string", note="dict route")
        opened = open_profile(container)
        self.assertEqual(opened.session.auth_key, KEY)
        self.assertEqual(opened.meta["note"], "dict route")
        self.assertIsNone(opened.path)

    def test_open_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            open_profile("/nonexistent/whatever.tgmint")

    def test_read_profile_on_a_foreign_json(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "x.tgmint")
        with open(path, "w", encoding="utf-8") as fp:
            fp.write('{"format": "someone-elses/1"}')
        with self.assertRaises(ProfileError) as ctx:
            read_profile(path)
        self.assertIn("someone-elses/1", str(ctx.exception))

        with open(path, "w", encoding="utf-8") as fp:
            fp.write("not json at all")
        with self.assertRaises(ProfileError):
            read_profile(path)

    def test_meta_is_stamped(self):
        container = seal(session(), "telethon-string")
        meta = container["meta"]
        self.assertEqual(sorted(meta), ["created", "note", "tgmint"])
        self.assertEqual(meta["note"], "")


class SessionPayloads(unittest.TestCase):
    def test_every_session_format_round_trips_the_key(self):
        for fmt in SESSION_FORMATS:
            with self.subTest(fmt=fmt):
                opened = open_profile(seal(session(), fmt))
                self.assertEqual(opened.session.auth_key, KEY)
                self.assertEqual(opened.session.dc_id, DC_ID)
                self.assertEqual(opened.session_format, fmt)

    def test_tdata_payload_is_its_telethon_string(self):
        container = seal(session(), "tdata")
        payload = container["session"]["data"]
        self.assertEqual(payload, telethon.write_string(session()))
        self.assertEqual(open_profile(container).session.auth_key, KEY)

    def test_bytes_payload_is_base64_and_round_trips(self):
        string = telethon.write_string(session())
        container = seal(string.encode("utf-8"), "telethon-string")
        self.assertEqual(container["session"]["encoding"], "base64")
        raw = base64.b64decode(container["session"]["data"])
        self.assertEqual(raw.decode("utf-8"), string)
        self.assertEqual(open_profile(container).session.auth_key, KEY)

    def test_seal_rejects_an_unknown_format(self):
        with self.assertRaises(ProfileError) as ctx:
            seal(session(), "hydrogram-string")
        self.assertIn("unknown session format", str(ctx.exception))

    def test_seal_rejects_an_unrepresentable_session(self):
        # a Pyrogram string stores user_id + api_id; a session without them
        # cannot be written into one
        with self.assertRaises(ProfileError) as ctx:
            seal(SessionData(dc_id=DC_ID, auth_key=KEY), "pyrogram-string")
        self.assertIn("pyrogram", str(ctx.exception).lower())

    def test_seal_rejects_bad_bytes(self):
        with self.assertRaises(ProfileError):
            seal(b"definitely not a session string", "telethon-string")
        with self.assertRaises(ProfileError):
            seal(b"", "telethon-string")

    def test_seal_rejects_a_non_session_object(self):
        with self.assertRaises(ProfileError):
            seal("1c29tZXN0cmluZw==", "telethon-string")  # type: ignore[arg-type]

    def test_passkey_payload_must_be_a_store(self):
        with self.assertRaises(ProfileError) as ctx:
            seal(session(), "telethon-string", passkey={"user_handle": "2:1"})
        self.assertIn("private_key", str(ctx.exception))
        with self.assertRaises(ProfileError):
            seal(session(), "telethon-string", passkey="nope")


class Correlation(unittest.TestCase):
    """Cross-validation: the envelope's parts must describe one account.

    ``seal()`` refuses a mismatched set of parts (it must never publish an
    envelope ``open_profile`` would reject), so a deliberately broken
    container for the read-side cases is assembled by hand with
    :func:`broken_container` — the shape ``seal()`` writes, minus the
    validation.
    """

    def test_seal_refuses_a_fingerprint_user_id_mismatch(self):
        with self.assertRaises(ProfileError) as ctx:
            seal(
                session(user_id=111),
                "pyrogram-string",
                fingerprint=fingerprint_data(user_id=222),
            )
        message = str(ctx.exception)
        self.assertIn("111", message)
        self.assertIn("222", message)
        self.assertIn("user_id", message)

    def test_seal_refuses_a_fingerprint_dc_mismatch(self):
        with self.assertRaises(ProfileError) as ctx:
            seal(
                session(dc_id=2),
                "telethon-string",
                fingerprint=fingerprint_data(dc_id=4),
            )
        self.assertIn("dc_id", str(ctx.exception))

    def test_seal_refuses_another_accounts_passkey(self):
        with self.assertRaises(ProfileError) as ctx:
            seal(
                session(user_id=111),
                "pyrogram-string",
                passkey=passkey_store(user_id=999),
            )
        message = str(ctx.exception)
        self.assertIn("passkey", message)
        self.assertIn("999", message)

    def test_seal_refuses_an_unloadable_fingerprint_dict(self):
        # an identity open_profile could not load back is refused at seal
        # time instead of published as an unopenable envelope
        with self.assertRaises(ProfileError) as ctx:
            seal(session(), "telethon-string", fingerprint={"api_id": 1})
        self.assertIn("fingerprint", str(ctx.exception))

    def test_fingerprint_user_id_mismatch(self):
        # pyrogram-string is the codec string that keeps user_id, so the
        # cross-check has something to compare against
        container = broken_container(
            session(user_id=111),
            "pyrogram-string",
            fingerprint=fingerprint_data(user_id=222),
        )
        with self.assertRaises(ProfileError) as ctx:
            open_profile(container)
        message = str(ctx.exception)
        self.assertIn("111", message)
        self.assertIn("222", message)
        self.assertIn("user_id", message)

    def test_fingerprint_dc_mismatch(self):
        container = broken_container(
            session(dc_id=2),
            "telethon-string",
            fingerprint=fingerprint_data(dc_id=4),
        )
        with self.assertRaises(ProfileError) as ctx:
            open_profile(container)
        message = str(ctx.exception)
        self.assertIn("dc_id", message)
        self.assertIn("2", message)
        self.assertIn("4", message)

    def test_passkey_of_another_account(self):
        container = broken_container(
            session(user_id=111),
            "pyrogram-string",
            passkey=passkey_store(user_id=999),
        )
        with self.assertRaises(ProfileError) as ctx:
            open_profile(container)
        message = str(ctx.exception)
        self.assertIn("passkey", message)
        self.assertIn("111", message)
        self.assertIn("999", message)

    def test_crafted_non_integer_ids_raise_profile_error(self):
        # a crafted container must never escape as a bare TypeError from
        # int(): one exception type covers every read-side failure
        for fingerprint in (
            fingerprint_data(user_id=[1, 2]),
            fingerprint_data(user_id={"id": 1}),
            fingerprint_data(dc_id=object()),
            fingerprint_data(dc_id=[4]),
            fingerprint_data(user_id=1.5),
        ):
            with self.subTest(fingerprint=fingerprint):
                with self.assertRaises(ProfileError):
                    open_profile(
                        broken_container(
                            session(), "pyrogram-string", fingerprint=fingerprint
                        )
                    )

    def test_matching_parts_are_accepted(self):
        container = seal(
            session(user_id=555),
            "pyrogram-string",
            fingerprint=fingerprint_data(user_id=555, dc_id=DC_ID),
            passkey=passkey_store(user_id=555),
        )
        opened = open_profile(container)
        self.assertEqual(opened.session.user_id, 555)

    def test_unknown_parts_are_not_guessed_at(self):
        # a telethon string stores no user_id, so a passkey for anyone can
        # only be checked when the session knows its own user id
        container = seal(
            SessionData(dc_id=DC_ID, auth_key=KEY),
            "telethon-string",
            passkey=passkey_store(),
        )
        self.assertIsNone(open_profile(container).session.user_id)

    def test_unusable_fingerprint_is_an_error(self):
        container = seal(session(), "telethon-string")
        container["fingerprint"] = {"api_id": 1}
        with self.assertRaises(ProfileError) as ctx:
            open_profile(container)
        self.assertIn("fingerprint", str(ctx.exception))

    def test_broken_session_payload_is_an_error(self):
        container = seal(session(), "telethon-string")
        container["session"]["data"] = "1" + base64.urlsafe_b64encode(
            os.urandom(12)
        ).decode()
        with self.assertRaises(ProfileError) as ctx:
            open_profile(container)
        self.assertIn("does not parse", str(ctx.exception))


_COUNTER = iter(range(1000))


@unittest.skipUnless(HAVE_CRYPTO, "the seal needs cryptography")
class SealedRoundTrip(unittest.TestCase):
    PASSPHRASE = "correct horse battery staple"

    def _sealed_file(self, tmp, passphrase=PASSPHRASE, name="sealed.tgmint"):
        path = os.path.join(tmp, name)
        container = seal(
            session(),
            "telethon-string",
            fingerprint=fingerprint(),
            passkey=passkey_store(),
            passphrase=passphrase,
            note="sealed",
        )
        write_profile(container, path)
        return path

    def test_round_trip(self):
        tmp = tempfile.mkdtemp()
        path = self._sealed_file(tmp)
        opened = open_profile(path, passphrase=self.PASSPHRASE)
        self.assertTrue(opened.sealed)
        self.assertEqual(opened.session.auth_key, KEY)
        self.assertEqual(opened.fingerprint, fingerprint())
        self.assertEqual(opened.passkey["user_handle"], f"{DC_ID}:{USER_ID}")
        self.assertEqual(opened.meta["note"], "sealed")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_sealed_file_leaks_nothing(self):
        tmp = tempfile.mkdtemp()
        path = self._sealed_file(tmp)
        with open(path, "rb") as fp:
            raw = fp.read()
        self.assertEqual(sorted(json.loads(raw)), ["format", "sealed"])
        self.assertNotIn(self.PASSPHRASE.encode(), raw)
        self.assertNotIn(KEY, raw)
        self.assertNotIn(base64.b64encode(KEY), raw)
        self.assertNotIn(b"user_handle", raw)
        self.assertNotIn(b"private_key", raw)

        sealed = json.loads(raw)["sealed"]
        self.assertEqual(sealed["kdf"], KDF)
        self.assertEqual(sealed["iterations"], ITERATIONS)
        self.assertEqual(len(base64.b64decode(sealed["salt"])), 16)
        self.assertEqual(len(base64.b64decode(sealed["nonce"])), 12)

    def test_sealing_is_randomized(self):
        tmp = tempfile.mkdtemp()
        first = seal(session(), "telethon-string", passphrase=self.PASSPHRASE)
        second = seal(session(), "telethon-string", passphrase=self.PASSPHRASE)
        self.assertNotEqual(first["sealed"]["salt"], second["sealed"]["salt"])
        self.assertNotEqual(first["sealed"]["nonce"], second["sealed"]["nonce"])
        self.assertNotEqual(
            first["sealed"]["ciphertext"], second["sealed"]["ciphertext"]
        )
        for container in (first, second):  # both still open
            self.assertEqual(
                open_profile(container, passphrase=self.PASSPHRASE).session.auth_key,
                KEY,
            )

    def test_wrong_passphrase(self):
        tmp = tempfile.mkdtemp()
        path = self._sealed_file(tmp)
        with self.assertRaises(ProfileError) as ctx:
            open_profile(path, passphrase="wrong")
        message = str(ctx.exception)
        self.assertIn("wrong passphrase", message)
        self.assertIn("tampered", message)

    def test_missing_passphrase(self):
        tmp = tempfile.mkdtemp()
        path = self._sealed_file(tmp)
        with self.assertRaises(ProfileError) as ctx:
            open_profile(path)
        self.assertIn("sealed", str(ctx.exception))
        self.assertIn("passphrase", str(ctx.exception))

    def _tampered(self, tmp, mutate):
        path = self._sealed_file(tmp, name=f"sealed-{next(_COUNTER)}.tgmint")
        with open(path, encoding="utf-8") as fp:
            raw = json.load(fp)
        mutate(raw["sealed"])
        broken = os.path.join(tmp, "broken.tgmint")
        with open(broken, "w", encoding="utf-8") as fp:
            json.dump(raw, fp)
        return broken

    def test_tampered_ciphertext(self):
        tmp = tempfile.mkdtemp()

        def flip(sealed):
            blob = bytearray(base64.b64decode(sealed["ciphertext"]))
            blob[len(blob) // 2] ^= 0x01
            sealed["ciphertext"] = base64.b64encode(bytes(blob)).decode()

        path = self._tampered(tmp, flip)
        with self.assertRaises(ProfileError) as ctx:
            open_profile(path, passphrase=self.PASSPHRASE)
        self.assertIn("AES-256-GCM", str(ctx.exception))

    def test_tampered_salt_and_nonce(self):
        tmp = tempfile.mkdtemp()
        for field in ("salt", "nonce"):
            with self.subTest(field=field):
                def mangle(sealed, field=field):
                    blob = bytearray(base64.b64decode(sealed[field]))
                    blob[0] ^= 0xFF
                    sealed[field] = base64.b64encode(bytes(blob)).decode()

                path = self._tampered(tmp, mangle)
                with self.assertRaises(ProfileError):
                    open_profile(path, passphrase=self.PASSPHRASE)

    def test_unsupported_kdf_and_absurd_iterations(self):
        tmp = tempfile.mkdtemp()
        for field, value, needle in (
            ("kdf", "argon2id", "unsupported seal KDF"),
            ("iterations", 0, "outside the sane range"),
            ("iterations", 10**9, "outside the sane range"),
            ("iterations", "many", "iterations"),
            ("ciphertext", "!!!not base64!!!", "malformed"),
        ):
            with self.subTest(field=field, value=value):
                def mutate(sealed, field=field, value=value):
                    sealed[field] = value

                path = self._tampered(tmp, mutate)
                with self.assertRaises(ProfileError) as ctx:
                    open_profile(path, passphrase=self.PASSPHRASE)
                self.assertIn(needle, str(ctx.exception))

    def test_seal_needs_crypto(self):
        with no_crypto():
            with self.assertRaises(ProfileError) as ctx:
                seal(session(), "telethon-string", passphrase="x")
        message = str(ctx.exception)
        self.assertIn("passkeys", message)
        self.assertIn("cryptography", message)

    def test_unsealed_seal_needs_no_crypto(self):
        # an unsealed profile is the portable-everywhere form: no crypto,
        # no extra, no import
        with no_crypto():
            container = seal(session(), "telethon-string")
            opened = open_profile(container)
        self.assertEqual(opened.session.auth_key, KEY)


class Inspection(unittest.TestCase):
    def test_inspect_plain(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "acct.tgmint")
        write_profile(
            seal(
                session(),
                "pyrogram-string",
                fingerprint=fingerprint(),
                passkey=passkey_store(),
                note="inspected",
            ),
            path,
        )
        summary = inspect_profile(path)
        self.assertEqual(summary["format"], FORMAT)
        self.assertFalse(summary["sealed"])
        self.assertFalse(summary["locked"])
        self.assertEqual(summary["session_format"], "pyrogram-string")
        self.assertEqual(summary["dc_id"], DC_ID)
        self.assertEqual(summary["user_id"], USER_ID)
        self.assertTrue(summary["has_fingerprint"])
        self.assertTrue(summary["has_passkey"])
        self.assertEqual(summary["fingerprint"]["device_model"], "Desktop")
        self.assertEqual(summary["passkey"]["name"], "tgmint software passkey")
        self.assertEqual(summary["meta"]["note"], "inspected")
        # no secret ever leaves this summary
        self.assertNotIn(KEY.hex(), json.dumps(summary))
        self.assertNotIn("private_key", json.dumps(summary))

    @unittest.skipUnless(HAVE_CRYPTO, "the seal needs cryptography")
    def test_inspect_sealed_locked_and_unlocked(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "sealed.tgmint")
        write_profile(
            seal(session(), "telethon-string", passphrase="s3cret"), path
        )
        locked = inspect_profile(path)
        self.assertTrue(locked["sealed"])
        self.assertTrue(locked["locked"])
        self.assertEqual(locked["kdf"], KDF)
        self.assertEqual(locked["iterations"], ITERATIONS)
        self.assertIsNone(locked["session_format"])
        self.assertIsNone(locked["dc_id"])

        opened = inspect_profile(path, passphrase="s3cret")
        self.assertFalse(opened["locked"])
        self.assertEqual(opened["session_format"], "telethon-string")
        self.assertEqual(opened["dc_id"], DC_ID)


class CodecIntegration(unittest.TestCase):
    """The envelope as a `convert` source — and only a source."""

    def _profile_file(self, tmp, passphrase=None, name="acct.tgmint"):
        path = os.path.join(tmp, name)
        write_profile(
            seal(
                session(),
                "telethon-string",
                fingerprint=fingerprint(),
                passphrase=passphrase,
            ),
            path,
        )
        return path

    def test_convert_session_from_profile(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp)
        out = os.path.join(tmp, "out.gramjs")
        result = codec.convert_session(source, "profile", out, "gramjs-string")
        self.assertEqual(result["source_format"], "profile")
        self.assertEqual(result["dc_id"], DC_ID)
        self.assertEqual(gramjs.read_string(open(out, encoding="ascii").read()).auth_key, KEY)

    def test_convert_session_to_pyrogram_from_profile(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp)
        out = os.path.join(tmp, "out.pyro")
        result = codec.convert_session(
            source, "profile", out, "pyrogram-string", user_id=USER_ID, api_id=API_ID
        )
        self.assertEqual(result["user_id"], USER_ID)
        self.assertEqual(
            pyrogram.read_string(open(out, encoding="ascii").read()).auth_key, KEY
        )

    @unittest.skipUnless(HAVE_CRYPTO, "the seal needs cryptography")
    def test_convert_session_from_sealed_profile(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp, passphrase="pw")
        out = os.path.join(tmp, "out.telethon")
        with self.assertRaises(codec.CodecError) as ctx:
            codec.convert_session(source, "profile", out, "telethon-string")
        self.assertIn("sealed", str(ctx.exception))
        self.assertFalse(os.path.exists(out))

        codec.convert_session(
            source, "profile", out, "telethon-string", passphrase="pw"
        )
        self.assertEqual(
            telethon.read_string(open(out, encoding="ascii").read()).auth_key, KEY
        )

    def test_format_aliases_and_inference(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp)
        for alias in ("profile", "tgmint", "tgmint-profile", "tgmint-profile/1"):
            with self.subTest(alias=alias):
                out = os.path.join(tmp, f"out-{alias.replace('/', '-')}.txt")
                codec.convert_session(source, alias, out, "telethon-string")
                self.assertTrue(os.path.isfile(out))
        self.assertEqual(codec.infer_source_format(source), "profile")
        self.assertEqual(codec.infer_source_format("acct.session"), "telethon-session")
        # None means "infer", not "unknown"
        out = os.path.join(tmp, "inferred.txt")
        codec.convert_session(source, None, out, "telethon-string")
        self.assertTrue(os.path.isfile(out))

    def test_profile_is_not_a_destination(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp)
        with self.assertRaises(codec.CodecError):
            codec.convert_session(
                source, "profile", os.path.join(tmp, "x.tgmint"), "profile"
            )

    def test_read_session_from_profile(self):
        tmp = tempfile.mkdtemp()
        source = self._profile_file(tmp)
        self.assertEqual(codec.read_session(source, "profile").auth_key, KEY)
        self.assertEqual(codec.read_session(source).auth_key, KEY)  # inferred

    def test_profile_from_a_sqlite_session_file(self):
        # end to end: write a real telethon SQLite session, seal it, read it
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "real.session")
        telethon.write_sqlite(session(), db)
        data = codec.read_session(db, "telethon-session")
        path = os.path.join(tmp, "from-sqlite.tgmint")
        write_profile(seal(data, "telethon-session"), path)
        opened = open_profile(path)
        self.assertEqual(opened.session.auth_key, KEY)
        self.assertEqual(opened.session_format, "telethon-session")
        out = os.path.join(tmp, "back.session")
        codec.convert_session(path, "profile", out, "telethon-session")
        self.assertEqual(codec.read_session(out, "telethon-session").auth_key, KEY)


class GuessFormat(unittest.TestCase):
    def test_suffix_and_fallback(self):
        self.assertEqual(guess_format("x.tgmint"), "profile")
        self.assertEqual(guess_format("/tmp/a/b.tgmint"), "profile")
        self.assertEqual(guess_format("x.session"), "telethon-session")
        self.assertEqual(guess_format("/tmp/tdata"), "telethon-session")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
