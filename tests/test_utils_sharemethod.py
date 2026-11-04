"""Regression tests for ``tgmint.utils.sharemethod``.

``sharemethod`` is a metaclass that lets ONE implementation serve as a
method on the class *and* on its instances: ``APIData.copy()``,
``api.copy()``, ``APIData.get_cls()`` and ``APIData.__str__`` all go through
it. Review finding #57: ``__call__`` used to forward ``*args`` only, so any
caller passing a keyword argument to a shared method got a
``TypeError: __call__() got an unexpected keyword argument``.

Also pins the ``extend_class`` metadata rule that Python 3.13 made visible
(``__firstlineno__``/``__static_attributes__`` are compiler metadata and
must not be copied onto the base class) — same file because both live in
``tgmint.utils`` and both are about class-level attribute plumbing.
"""

import unittest

from tgmint.utils import extend_class, sharemethod


class ShareMethodTest(unittest.TestCase):
    def test_kwargs_reach_the_shared_method(self):
        class Shared:
            # the metaclass instance is the class attribute; ``self`` is the
            # class when the attribute is read from the class
            @sharemethod
            def describe(self, *, prefix="", suffix=""):
                who = "class" if self is Shared else "instance"
                return f"{prefix}{who}{suffix}"

        self.assertEqual(Shared.describe(prefix="<", suffix=">"), "<class>")
        self.assertEqual(Shared().describe(prefix="<", suffix=">"), "<instance>")
        # positional and keyword arguments mix freely
        self.assertEqual(Shared.describe(suffix="!"), "class!")

    def test_the_class_and_the_instance_share_one_implementation(self):
        # this is the point of the helper: no __str__/copy duplication
        class Shared:
            @sharemethod
            def owner_name(self):
                return self.__name__ if isinstance(self, type) else type(self).__name__

        self.assertEqual(Shared.owner_name(), "Shared")
        self.assertEqual(Shared().owner_name(), "Shared")

    def test_api_apidata_copy_is_shared_by_class_and_instance(self):
        # the real callers: APIData.copy / .get_cls / .__str__ are shared
        from tgmint.api import API

        fp = API.TelegramDesktop.Generate(unique_id="sharemethod-kwargs")
        clone = fp.copy()
        self.assertEqual((clone.api_id, clone.device_model), (fp.api_id, fp.device_model))
        self.assertEqual(fp.get_cls(), type(fp))
        self.assertEqual(type(fp).get_cls(), type(fp))
        # the class-level form builds a fresh instance from the class fields
        self.assertEqual(type(fp.copy()).__name__, type(fp).__name__)


class ExtendClassMetadataTest(unittest.TestCase):
    def test_python_313_class_metadata_is_not_copied_onto_the_base(self):
        # Python 3.13 puts __firstlineno__ / __static_attributes__ in every
        # class __dict__; copying them onto the base raised
        # "already exists ... not marked @override" at import time
        class Base:
            def existing(self):
                return "base"

        before = {
            key: Base.__dict__[key]
            for key in ("__firstlineno__", "__static_attributes__")
            if key in Base.__dict__
        }

        @extend_class
        class Extension(Base):
            def added(self):
                self.marker = True
                return "added"

        self.assertEqual(Base().added(), "added")
        self.assertEqual(Base().existing(), "base")
        for key, value in before.items():
            with self.subTest(key=key):
                self.assertEqual(Base.__dict__[key], value)
        for key in ("__firstlineno__", "__static_attributes__"):
            if key in before:
                continue
            self.assertNotIn(key, Base.__dict__)

    def test_the_telethon_layer_still_imports(self):
        # the decorating class is used by tgmint.tl.telethon; a metadata leak
        # there surfaces as an import-time RuntimeError
        from tgmint.tl.telethon import TelegramClient  # noqa: F401
