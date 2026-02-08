#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from message_text_compression import (
    MODE_BZ2,
    MODE_DEFLATE,
    MODE_BYTE_DICT,
    MODE_FIXED_BITS,
    MODE_LZMA,
    MODE_ZLIB,
    CompressionCRCError,
    CompressionFormatError,
    mode_name,
    compress_text,
    decompress_text,
    should_compress,
)

ALL_MODES = (
    MODE_BYTE_DICT,
    MODE_FIXED_BITS,
    MODE_DEFLATE,
    MODE_ZLIB,
    MODE_BZ2,
    MODE_LZMA,
)


class MessageTextCompressionTests(unittest.TestCase):
    def _roundtrip(self, text: str, mode: int, preserve_case: bool = False) -> str:
        blob = compress_text(text, mode=mode, preserve_case=preserve_case)
        return decompress_text(blob)

    def test_roundtrip_empty(self) -> None:
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip("", mode), "")

    def test_roundtrip_russian(self) -> None:
        text = "привет как дела в сети все работает отлично"
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_roundtrip_mixed_ru_en(self) -> None:
        text = "mesh сеть работает отлично, retries ok, payload small"
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_roundtrip_with_punctuation_and_brackets(self) -> None:
        text = 'привет (тест), ок? "да"!'
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_roundtrip_with_emoji(self) -> None:
        text = "привет 😊 как дела 🚀"
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_roundtrip_long_unknown_token(self) -> None:
        # Keep token <= 64 UTF-8 bytes to satisfy escape-size guard.
        token = "длинноесловодлясжатия"
        text = f"{token} тест"
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_preserve_case(self) -> None:
        text = "Privet Как Дела TEST"
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode, preserve_case=True), text)

    def test_roundtrip_preserves_whitespace_exactly(self) -> None:
        text = "  привет,\n\tмир!  "
        for mode in ALL_MODES:
            self.assertEqual(self._roundtrip(text, mode), text)

    def test_invalid_crc(self) -> None:
        blob = bytearray(compress_text("привет", mode=MODE_BYTE_DICT))
        blob[-1] ^= 0x01
        with self.assertRaises(CompressionCRCError):
            decompress_text(bytes(blob))

    def test_invalid_magic(self) -> None:
        blob = bytearray(compress_text("привет", mode=MODE_BYTE_DICT))
        blob[0] = 0x00
        with self.assertRaises(CompressionFormatError):
            decompress_text(bytes(blob))

    def test_invalid_version(self) -> None:
        blob = bytearray(compress_text("привет", mode=MODE_BYTE_DICT))
        blob[2] = 0x7F
        # Fix crc to ensure version check path.
        from message_text_compression import _crc8  # type: ignore
        blob[-1] = _crc8(bytes(blob[:-1]))
        with self.assertRaises(CompressionFormatError):
            decompress_text(bytes(blob))

    def test_plain_payload_compatibility_path(self) -> None:
        text = "обычный utf8 без сжатия"
        payload = text.encode("utf-8")
        self.assertEqual(payload.decode("utf-8"), text)
        with self.assertRaises(CompressionFormatError):
            decompress_text(payload)

    def test_should_compress_returns_bool(self) -> None:
        self.assertIsInstance(should_compress("коротко"), bool)
        self.assertIsInstance(should_compress("это очень длинное сообщение " * 8), bool)

    def test_mode_name_labels(self) -> None:
        self.assertEqual(mode_name(MODE_BYTE_DICT), "mc_byte_dict")
        self.assertEqual(mode_name(MODE_FIXED_BITS), "mc_fixed_bits")
        self.assertEqual(mode_name(MODE_DEFLATE), "mc_deflate")
        self.assertEqual(mode_name(MODE_ZLIB), "mc_zlib")
        self.assertEqual(mode_name(MODE_BZ2), "mc_bz2")
        self.assertEqual(mode_name(MODE_LZMA), "mc_lzma")


if __name__ == "__main__":
    unittest.main()
