"""Regression tests for tgmint.utils.extend_class (Python 3.13 class metadata)."""

import unittest

from tgmint.utils import extend_class


class ExtendClassMetadataTest(unittest.TestCase):
    def test_extension_adds_methods_but_not_class_metadata(self):
        class Base:
            def existing(self):
                return "base"

        base_metadata = {
            k: Base.__dict__[k]
            for k in ("__firstlineno__", "__static_attributes__", "__module__", "__doc__")
            if k in Base.__dict__
        }

        # On Python 3.13+ this class body gets its own __firstlineno__ and
        # __static_attributes__; extending must not raise and must not copy them.
        @extend_class
        class Extension(Base):
            def added(self):
                self.marker = True
                return "added"

        self.assertEqual(Base().added(), "added")
        self.assertEqual(Base().existing(), "base")
        for key, value in base_metadata.items():
            with self.subTest(key=key):
                self.assertEqual(Base.__dict__[key], value)
        self.assertNotIn("__firstlineno__", {k for k in vars(Base) if k not in base_metadata})
        self.assertNotIn("__static_attributes__", {k for k in vars(Base) if k not in base_metadata})

    def test_telethon_layer_imports(self):
        # Before the fix, Python 3.13 raised RuntimeError at import time.
        from tgmint.tl.telethon import TelegramClient  # noqa: F401


if __name__ == "__main__":
    unittest.main()
