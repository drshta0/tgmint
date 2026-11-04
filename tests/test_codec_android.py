"""Offline tests for tgmint.codec.android — the android-dir source codec.

Golden fixtures are SYNTHESIZED: a tiny encoder in this file (written
straight from the DrKLO serialization this reader cites, and identical to
the executable spec it was validated against)
emits ``tgnet.dat`` + ``userconfing*.xml`` from known values.  No real
account data appears anywhere, and no test touches the network.

Verification status (honest): the format spec is verified line-by-line
against the official client source (commit pinned in
``tgmint/codec/android.py``) and cross-checked against AndroidTelePorter
(MIT); everything below proves this *reader* against an *independent*
writer, and every sink round-trip against this matrix's own codecs.
"""

import base64
import os
import struct
import tempfile
import unittest

from tgmint.codec import (
    CodecError,
    android,
    convert_session,
    gramjs,
    infer_source_format,
    pyrogram,
    read_session,
    telethon,
    write_session,
)
from tgmint.codec.data import SessionData

try:  # the tdata sink routes through tgmint.td (needs tgcrypto)
    import tgmint.td  # noqa: F401
    from tgmint.codec import tdata

    HAVE_TD = True
except Exception:  # pragma: no cover - optional dependency absent
    HAVE_TD = False

try:  # the envelope sink needs the profile module (stdlib until sealed)
    from tgmint import profile

    HAVE_PROFILE = True
except Exception:  # pragma: no cover
    HAVE_PROFILE = False

from tgmint.codec.android import OFFICIAL_APP_API_ID


KEY = bytes(range(256))                      # account 0's auth key
KEY1 = bytes(range(255, -1, -1))             # account 1's auth key
USER_ID = 123456789
USER_ID1 = 987654321
DC_ID = 2
ADDRESS = "149.154.167.51"
PORT = 443
LANG_CODE = "en"
VERSION_CODE = 7229  # app 13.1.x-era versionCode (the app's own, not a claim)

TRUE = 0x997275B5
FALSE = 0xBC799737


# ---------------------------------------------------------------------------
# the independent fixture encoder (mirrors DrKLO saveConfigInternal; never
# imports the reader it is testing against)
# ---------------------------------------------------------------------------

class _Write:
    """tgnet NativeByteBuffer wire encoding (little-endian, TL strings)."""

    def __init__(self):
        self.data = bytearray()

    def uint32(self, v):
        self.data += struct.pack("<I", v)
        return self

    def int32(self, v):
        self.data += struct.pack("<i", v)
        return self

    def int64(self, v):
        self.data += struct.pack("<q", v)
        return self

    def boolean(self, v):
        return self.uint32(TRUE if v else FALSE)

    def tl_bytes(self, b):
        n = len(b)
        if n < 254:
            self.data.append(n)
            head = 1
        else:
            self.data.append(254)
            self.data += n.to_bytes(3, "little")
            head = 4
        self.data += b
        self.data += b"\x00" * (-(n + head) % 4)
        return self

    def string(self, s):
        return self.tl_bytes(s.encode())


def encode_tgnet_dat(
    *,
    current_dc=DC_ID,
    auth_key=KEY,
    lang_code=LANG_CODE,
    version_code=VERSION_CODE,
    test_backend=False,
    has_current_dc=True,
    authorized=True,
    extra_dc_ids=(),
    with_salts=False,
    with_temp_keys=False,
):
    """One tgnet.dat: config v5 + one v13 datacenter stream per DC.

    The current DC carries `auth_key` and the app's real endpoint shape;
    extra DCs get a null key (exactly what a logged-out mirror looks
    like).  `with_salts`/`with_temp_keys` fill the optional blocks so the
    reader is proven against non-empty ones too.
    """
    b = _Write()
    b.uint32(5).boolean(test_backend).boolean(False)
    b.string(lang_code)
    b.boolean(has_current_dc)
    if has_current_dc:
        b.uint32(current_dc).int32(0).int32(0).int64(0x5EED)
        b.boolean(True).int32(1_700_000_000)
        b.uint32(0)  # sessionsToDestroy
        streams = [current_dc] + list(extra_dc_ids)
        b.uint32(len(streams))
        for dc_id in streams:
            this_dc = dc_id == current_dc
            key = auth_key if this_dc else b""
            b.uint32(13).uint32(dc_id)
            b.uint32(version_code).uint32(version_code)
            # ipv4
            b.uint32(1).string(ADDRESS).uint32(PORT).int32(0).string("")
            # ipv6, ipv4-download, ipv6-download
            b.uint32(0)
            b.uint32(0)
            b.uint32(0)
            b.boolean(False)  # isCdn
            b.uint32(len(key))
            b.data += key
            b.int64(0xA11CE if key else 0)
            if with_temp_keys:
                b.uint32(64)
                b.data += bytes(dc_id % 256 for _ in range(64))
                b.int64(0xB0B)
            else:
                b.uint32(0)
            b.int64(0)
            b.uint32(0)  # authKeyMediaTemp
            b.int64(0)
            b.int32(1 if (authorized or not this_dc) else 0)
            b.uint32(1 if (with_salts and this_dc) else 0)
            if with_salts and this_dc:
                b.int32(1_700_000_000).int32(1_800_000_000).int64(0x5A17)
            b.uint32(0)  # mediaServerSalts
    payload = bytes(b.data)
    return struct.pack("<I", len(payload)) + payload


def user_blob(user_id, constructor=0xB1B8CC83):
    """A serialized TLRPC.User that carries `user_id`.

    0xB1B8CC83 = current TL_user (constructor, flags, flags2, id:i64,
    then flag-gated fields — a first_name is appended so the buffer is a
    realistic length and trailing fields are proven ignored);
    0x215C4438 = the 10.3.2-12.9.0 era (constructor, flags, id:i64);
    0xD3BC4B7A = userEmpty (constructor, id:i64).
    """
    if constructor == 0xB1B8CC83:
        # flags bit 1 set -> first_name follows; flags2 = 0.  A TL string
        # "user": length 4, payload, 3 alignment pad bytes
        return (
            struct.pack("<IIIq", constructor, 2, 0, user_id)
            + b"\x04user\x00\x00\x00"
        )
    if constructor == 0x215C4438:
        return struct.pack("<Iiq", constructor, 0, user_id)
    return struct.pack("<Iq", constructor, user_id)


def write_prefs(path, user_id, constructor=0xB1B8CC83, key="user"):
    """A SharedPreferences XML with the Java-wrapped Base64 user blob.

    Java's Base64.DEFAULT wraps at 76 columns — the wrapping is part of
    the fixture, deliberately.
    """
    blob = base64.encodebytes(user_blob(user_id, constructor)).decode()
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(
            "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
            "<map>\n"
            f'    <string name="{key}">{blob}</string>\n'
            '    <boolean name="someOtherPref" value="true" />\n'
            "</map>\n"
        )


def make_dump(
    root,
    *,
    layout="app",            # "app" | "files" | "flat"
    accounts=(0, 1),
    second_prefs=True,
    **encoder_kwargs,
):
    """Build a dump directory with per-account tgnet.dat + prefs.

    account 0 -> KEY / USER_ID (current TL_user constructor);
    account 1 -> KEY1 / USER_ID1 (the layer-184 constructor).
    Returns the path to hand to the reader.
    """
    if layout == "app":
        files = os.path.join(root, "files")
        prefs = os.path.join(root, "shared_prefs")
    else:
        files = prefs = root
    os.makedirs(files, exist_ok=True)
    os.makedirs(prefs, exist_ok=True)
    for index in accounts:
        directory = files if index == 0 else os.path.join(files, f"account{index}")
        os.makedirs(directory, exist_ok=True)
        key = KEY if index == 0 else KEY1
        kwargs = dict(encoder_kwargs)
        kwargs.setdefault("auth_key", key)
        with open(os.path.join(directory, "tgnet.dat"), "wb") as fp:
            fp.write(encode_tgnet_dat(**kwargs))
        if index == 1 and not second_prefs:
            continue
        name = "userconfing.xml" if index == 0 else f"userconfig{index}.xml"
        user_id = USER_ID if index == 0 else USER_ID1
        constructor = 0xB1B8CC83 if index == 0 else 0x215C4438
        write_prefs(os.path.join(prefs, name), user_id, constructor)
    return root


class TestRead(unittest.TestCase):
    """Known values in, known SessionData out."""

    def test_account_zero_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = android.read(make_dump(tmp))
            self.assertEqual(data.dc_id, DC_ID)
            self.assertEqual(data.auth_key, KEY)
            self.assertEqual(data.user_id, USER_ID)
            self.assertEqual(data.server_address, ADDRESS)
            self.assertEqual(data.port, PORT)
            self.assertFalse(data.test_mode)
            self.assertFalse(data.is_bot)
            self.assertEqual(data.api_id, OFFICIAL_APP_API_ID)
            self.assertEqual(data.api_id, 4)

    def test_account_index_selects_the_right_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp)
            first = android.read(dump, account_index=0)
            second = android.read(dump, account_index=1)
            self.assertEqual((first.auth_key, first.user_id), (KEY, USER_ID))
            self.assertEqual((second.auth_key, second.user_id), (KEY1, USER_ID1))
            # None means slot 0, never "guess" or "all"
            self.assertEqual(android.read(dump), first)

    def test_discovery_lists_slots_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(android.discover_accounts(make_dump(tmp)), [0, 1])
        with tempfile.TemporaryDirectory() as tmp:
            make_dump(tmp, accounts=(1,))  # account0 never existed
            self.assertEqual(android.discover_accounts(tmp), [1])

    def test_all_three_dump_layouts_read(self):
        for layout in ("app", "files", "flat"):
            with tempfile.TemporaryDirectory() as tmp:
                root = os.path.join(tmp, layout)
                os.makedirs(root)
                make_dump(root, layout=layout, accounts=(0,), second_prefs=False)
                data = android.read(root)
                self.assertEqual((data.auth_key, data.user_id), (KEY, USER_ID), layout)

    def test_bak_fallback_after_crashed_write(self):
        # Config.cpp:17-28: the app promotes a leftover .bak over a missing
        # main file; the reader accepts the same recovery
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp, accounts=(0,), second_prefs=False)
            tgnet = os.path.join(dump, "files", "tgnet.dat")
            os.rename(tgnet, tgnet + ".bak")
            self.assertEqual(android.read(dump).auth_key, KEY)

    def test_multiple_datacenters_pick_the_current_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp, accounts=(0,), second_prefs=False, extra_dc_ids=(4, 5))
            config = android.read_tgnet_dat(
                open(os.path.join(dump, "files", "tgnet.dat"), "rb").read()
            )
            self.assertEqual(sorted(config.datacenters), [2, 4, 5])
            self.assertEqual(android.read(dump).auth_key, KEY)

    def test_test_backend_maps_to_test_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp, accounts=(0,), second_prefs=False, test_backend=True)
            self.assertTrue(android.read(dump).test_mode)

    def test_salts_and_temp_keys_are_parsed_without_harm(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(
                tmp, accounts=(0,), second_prefs=False, with_salts=True, with_temp_keys=True
            )
            self.assertEqual(android.read(dump).auth_key, KEY)

    def test_both_user_constructors_and_user_empty(self):
        for constructor in (0xB1B8CC83, 0x215C4438, 0xD3BC4B7A):
            with tempfile.TemporaryDirectory() as tmp:
                dump = make_dump(tmp, accounts=(0,), second_prefs=False)
                write_prefs(
                    os.path.join(dump, "shared_prefs", "userconfing.xml"),
                    USER_ID,
                    constructor,
                )
                self.assertEqual(android.read(dump).user_id, USER_ID, hex(constructor))

    def test_unknown_user_constructor_leaves_user_id_unset(self):
        # a future TL_user must not break the import; the auth key is the
        # session, the id is a bonus — and never guessed
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp, accounts=(0,), second_prefs=False)
            write_prefs(
                os.path.join(dump, "shared_prefs", "userconfing.xml"),
                USER_ID,
                constructor=0xDEADBEEF,
            )
            data = android.read(dump)
            self.assertEqual(data.auth_key, KEY)
            self.assertIsNone(data.user_id)

    def test_missing_or_garbage_prefs_leave_user_id_unset(self):
        for blob in ("", "not base64!!", "AAAA", "===="):
            with tempfile.TemporaryDirectory() as tmp:
                dump = make_dump(tmp, accounts=(0,), second_prefs=False)
                path = os.path.join(dump, "shared_prefs", "userconfing.xml")
                with open(path, "w", encoding="utf-8") as fp:
                    fp.write(
                        '<?xml version="1.0"?><map>'
                        f'<string name="user">{blob}</string></map>'
                    )
                self.assertIsNone(android.read(dump).user_id, blob)
        with tempfile.TemporaryDirectory() as tmp:  # no prefs file at all
            dump = make_dump(tmp, accounts=(0,), second_prefs=False)
            os.remove(os.path.join(dump, "shared_prefs", "userconfing.xml"))
            self.assertIsNone(android.read(dump).user_id)
        with tempfile.TemporaryDirectory() as tmp:  # malformed XML
            dump = make_dump(tmp, accounts=(0,), second_prefs=False)
            path = os.path.join(dump, "shared_prefs", "userconfing.xml")
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("<map><string name=user>")
            self.assertIsNone(android.read(dump).user_id)

    def test_read_session_public_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp)
            self.assertEqual(read_session(dump, "android-dir").auth_key, KEY)
            self.assertEqual(
                read_session(dump, "android-dir", account_index=1).user_id, USER_ID1
            )

    def test_inference_detects_a_dump_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_dump(tmp, accounts=(0,), second_prefs=False)
            self.assertEqual(infer_source_format(tmp), "android-dir")
        self.assertEqual(infer_source_format("/nowhere/x.session"), "telethon-session")
        self.assertEqual(infer_source_format("/nowhere/x.tgmint"), "profile")


class TestErrors(unittest.TestCase):
    """Garbage in, the codec's typed error out — never struct.error."""

    def assertCodecError(self, context, dump):
        try:
            android.read(dump) if context == "read" else android.read_tgnet_dat(dump)
        except CodecError:
            return
        except Exception as exc:  # noqa: BLE001 - the point of the test
            self.fail(f"leaked {type(exc).__name__}: {exc}")
        self.fail("malformed dump did not raise")

    def test_not_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope")
            with self.assertRaises(FileNotFoundError):
                android.read(missing)

    def test_empty_directory_is_not_a_dump(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CodecError) as caught:
                android.read(tmp)
            self.assertIn("no tgnet.dat", str(caught.exception))

    def test_account_index_out_of_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp)
            with self.assertRaises(CodecError) as caught:
                android.read(dump, account_index=2)
            self.assertIn("available: [0, 1]", str(caught.exception))
            with self.assertRaises(CodecError):
                android.read(dump, account_index=-1)

    def test_truncated_at_every_offset(self):
        raw = encode_tgnet_dat()
        for cut in range(len(raw)):
            self.assertCodecError("dat", raw[:cut])

    def test_truncated_file_surfaces_the_typed_error(self):
        # byte-exact coverage is the test above; this one proves the
        # read() wrapper (path resolution included) raises the same typed
        # error rather than leaking a parser exception
        raw = encode_tgnet_dat()
        for cut in range(0, len(raw), 13):
            with tempfile.TemporaryDirectory() as tmp:
                dump = make_dump(tmp, accounts=(0,), second_prefs=False)
                with open(os.path.join(dump, "files", "tgnet.dat"), "wb") as fp:
                    fp.write(raw[:cut])
                self.assertCodecError("read", dump)

    def test_size_prefix_mismatch(self):
        raw = bytearray(encode_tgnet_dat())
        raw[0:4] = struct.pack("<I", len(raw) * 3)
        self.assertCodecError("dat", bytes(raw))

    def test_future_config_version_refused(self):
        raw = bytearray(encode_tgnet_dat())
        raw[4:8] = struct.pack("<i", 6)
        self.assertCodecError("dat", bytes(raw))
        with self.assertRaises(CodecError) as caught:
            android.read_tgnet_dat(bytes(raw))
        self.assertIn("config version 6", str(caught.exception))

    def test_future_dc_stream_version_refused(self):
        raw = bytearray(encode_tgnet_dat())
        # first datacenter stream begins after the fixed header + count;
        # locate the version word by rebuilding the header prefix length
        header = _Write()
        header.uint32(5).boolean(False).boolean(False).string(LANG_CODE)
        header.boolean(True).uint32(DC_ID).int32(0).int32(0).int64(0)
        header.boolean(True).int32(0).uint32(0).uint32(1)
        offset = 4 + len(header.data)
        raw[offset : offset + 4] = struct.pack("<I", 14)
        with self.assertRaises(CodecError) as caught:
            android.read_tgnet_dat(bytes(raw))
        self.assertIn("stream version 14", str(caught.exception))

    def test_bad_bool_constructor(self):
        raw = bytearray(encode_tgnet_dat())
        raw[8:12] = struct.pack("<I", 0x12345678)  # testBackend slot
        self.assertCodecError("dat", bytes(raw))

    def test_pure_garbage(self):
        for garbage in (b"", b"\x00" * 64, os.urandom(512), b"tgnet.dat text file"):
            self.assertCodecError("dat", garbage)

    def test_not_signed_in(self):
        # hasCurrentDc false: the app copy never completed a login
        self.assertCodecError("dat", encode_tgnet_dat(has_current_dc=False))
        # authorized=0 with an empty key on the current DC: slot logged out
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(
                tmp, accounts=(0,), second_prefs=False, authorized=False, auth_key=b""
            )
            with self.assertRaises(CodecError) as caught:
                android.read(dump)
            self.assertIn("not signed in", str(caught.exception))

    def test_android_dir_is_never_a_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CodecError):
                write_session(
                    SessionData(dc_id=DC_ID, auth_key=KEY),
                    os.path.join(tmp, "out"),
                    "android-dir",
                )


class TestEverySink(unittest.TestCase):
    """The android-dir source feeds every destination of the matrix."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dump = make_dump(cls._tmp.name)
        cls.data = android.read(cls.dump)
        cls._sequence = 0

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _convert(self, to_format, **kwargs):
        self._sequence += 1
        destination = os.path.join(
            self._tmp.name, f"out-{self._sequence}.{to_format}"
        )
        result = convert_session(
            self.dump, "android-dir", destination, to_format, **kwargs
        )
        self.assertEqual(result["source_format"], "android-dir")
        self.assertEqual(result["dc_id"], DC_ID)
        return result, destination

    def test_telethon_session(self):
        _, out = self._convert("telethon-session")
        data = telethon.read_sqlite(out)
        self.assertEqual(
            (data.dc_id, data.auth_key, data.server_address, data.port),
            (DC_ID, KEY, ADDRESS, PORT),
        )
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)

    def test_telethon_string(self):
        _, out = self._convert("telethon-string")
        with open(out, encoding="ascii") as fp:
            data = telethon.read_string(fp.read().strip())
        self.assertEqual((data.dc_id, data.auth_key), (DC_ID, KEY))
        self.assertEqual((data.server_address, data.port), (ADDRESS, PORT))

    def test_pyrogram_session_both_variants(self):
        for variant in ("pyrogram", "kurigram"):
            _, out = self._convert("pyrogram-session", variant=variant)
            data = pyrogram.read_sqlite(out)
            self.assertEqual(
                (data.dc_id, data.auth_key, data.user_id, data.api_id),
                (DC_ID, KEY, USER_ID, self.data.api_id),
                variant,
            )

    def test_pyrogram_string_carries_the_apps_own_api_id(self):
        result, out = self._convert("pyrogram-string")
        with open(out, encoding="ascii") as fp:
            data = pyrogram.read_string(fp.read().strip())
        # the official app's own wire api_id (4), never the 2040
        # placeholder 2040 a user_id-less source would have forced
        self.assertEqual(data.api_id, 4)
        self.assertEqual(data.user_id, USER_ID)
        self.assertEqual(data.auth_key, KEY)
        # the conversion report records where the api_id came from
        self.assertIn("android-dir source carried 4", " ".join(result["notes"]))
        self.assertNotIn("api_id", result.get("filled", []))

    def test_gramjs_string(self):
        _, out = self._convert("gramjs-string")
        with open(out, encoding="ascii") as fp:
            data = gramjs.read_string(fp.read().strip())
        self.assertEqual((data.dc_id, data.auth_key), (DC_ID, KEY))
        self.assertEqual(data.server_address, ADDRESS)

    def test_tdata_read_back_check(self):
        if not HAVE_TD:  # pragma: no cover - tgcrypto missing
            self.skipTest("tgmint.td (tgcrypto) not installed")
        result, out = self._convert("tdata")
        self.assertEqual(result["output_kind"], "tdata-directory")
        # the read-back check the research doc asked for: parse the
        # emitted tdata with our own reader and compare credentials
        back = tdata.read(out)
        self.assertEqual(back.auth_key, KEY)
        self.assertEqual(back.dc_id, DC_ID)
        self.assertEqual(back.user_id, USER_ID)

    def test_envelope_round_trip(self):
        if not HAVE_PROFILE:  # pragma: no cover
            self.skipTest("tgmint.profile not importable")
        # sealed as pyrogram-string: the envelope payload format that, like
        # the android source, keeps the account's user_id and api_id
        container = profile.seal(self.data, "pyrogram-string")
        envelope = os.path.join(self._tmp.name, "account.tgmint")
        profile.write_profile(container, envelope)
        opened = profile.open_profile(envelope)
        self.assertEqual(opened.session.auth_key, KEY)
        self.assertEqual(opened.session.user_id, USER_ID)
        self.assertEqual(opened.session.api_id, self.data.api_id)
        # and the envelope is itself a source of the matrix: full circle
        out = os.path.join(self._tmp.name, "from-envelope.session")
        result = convert_session(envelope, "profile", out, "telethon-session")
        self.assertEqual(telethon.read_sqlite(out).auth_key, KEY)
        self.assertEqual(result["source_format"], "profile")

    def test_account_index_flows_through_convert_session(self):
        destination = os.path.join(self._tmp.name, "second.session")
        convert_session(
            self.dump, "android-dir", destination, "telethon-session", account_index=1
        )
        self.assertEqual(telethon.read_sqlite(destination).auth_key, KEY1)


class TestPreserves(unittest.TestCase):
    """The honest PRESERVES table matches what reads actually return."""

    def test_table_is_field_accurate(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = android.read(make_dump(tmp, accounts=(0,), second_prefs=False))
            for field in android.PRESERVES:
                self.assertIsNotNone(getattr(data, field), field)

    def test_reported_preserved_fields_of_a_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "p.session")
            result = convert_session(
                make_dump(tmp, accounts=(0,), second_prefs=False),
                "android-dir",
                out,
                "pyrogram-session",
            )
            for field in ("dc_id", "auth_key", "user_id", "api_id"):
                self.assertIn(field, result["preserved"])


class TestCLI(unittest.TestCase):
    """`tgmint convert --from-format android-dir` end to end."""

    def _run(self, argv):
        import contextlib
        import io
        import json

        from tgmint import cli

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue(), json

    def test_convert_to_telethon_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp)
            out = os.path.join(tmp, "out.session")
            code, out_txt, err, _json = self._run(
                [
                    "convert",
                    "--from", dump,
                    "--from-format", "android-dir",
                    "--to", out,
                    "--to-format", "telethon-session",
                ]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("converted", out_txt)
            self.assertIn(f"dc_id: {DC_ID}", out_txt)
            self.assertEqual(telethon.read_sqlite(out).auth_key, KEY)

    def test_account_index_and_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp)
            out = os.path.join(tmp, "second.session")
            code, out_txt, err, json = self._run(
                [
                    "convert",
                    "--from", dump,
                    "--from-format", "android-dir",
                    "--to", out,
                    "--to-format", "pyrogram-session",
                    "--variant", "kurigram",
                    "--account-index", "1",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out_txt)
            self.assertEqual(payload["from_format"], "android-dir")
            self.assertEqual(payload["result"]["dc_id"], DC_ID)
            data = pyrogram.read_sqlite(out)
            self.assertEqual(data.auth_key, KEY1)
            self.assertEqual(data.user_id, USER_ID1)

    def test_bad_index_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = make_dump(tmp, accounts=(0,), second_prefs=False)
            out = os.path.join(tmp, "out.session")
            code, _out, err, _json = self._run(
                [
                    "convert",
                    "--from", dump,
                    "--from-format", "android-dir",
                    "--to", out,
                    "--to-format", "telethon-session",
                    "--account-index", "3",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("convert failed", err)
            self.assertIn("available: [0]", err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
