# -----------------------------------------------------------------------------
#
# Smoke tests for CVE-remediated dependency upgrades.
# Verifies upgraded packages import correctly and core APIs used
# by this project still function.
#
# -----------------------------------------------------------------------------

import io

import pytest


class TestPillowUpgrade:
    """pillow 10.4.0 -> 12.1.1 (CVE-2026-25990)"""

    def test_import(self):
        from PIL import Image
        assert hasattr(Image, "open")

    def test_image_open(self):
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (10, 10), (255, 0, 0)).save(buf, format="PNG")
        buf.seek(0)
        img = Image.open(buf)
        assert img.size == (10, 10)

    def test_image_convert(self):
        from PIL import Image
        img = Image.new("RGBA", (4, 4))
        rgb = img.convert("RGB")
        assert rgb.mode == "RGB"

    def test_image_resize(self):
        from PIL import Image
        img = Image.new("RGB", (100, 100))
        resized = img.resize((50, 50))
        assert resized.size == (50, 50)


class TestProtobufUpgrade:
    """protobuf 6.31.0 -> >=6.33.5 (CVE-2025-4565, CVE-2026-0994)"""

    def test_import(self):
        import google.protobuf
        assert google.protobuf.__version__

    def test_core_modules(self):
        from google.protobuf import descriptor, message, descriptor_pool
        assert descriptor and message and descriptor_pool


class TestSentencepieceUpgrade:
    """sentencepiece 0.2.0 -> 0.2.1 (CVE-2026-1260)"""

    def test_import(self):
        import sentencepiece
        assert hasattr(sentencepiece, "SentencePieceProcessor")

    def test_processor_instantiation(self):
        import sentencepiece
        sp = sentencepiece.SentencePieceProcessor()
        assert sp is not None


class TestSetuptoolsUpgrade:
    """setuptools >=62.0.0 -> >=78.1.1 (CVE-2025-47273)"""

    def test_import(self):
        import setuptools
        assert hasattr(setuptools, "__version__")

    def test_version_minimum(self):
        import setuptools
        from packaging.version import Version
        assert Version(setuptools.__version__) >= Version("78.1.1")
