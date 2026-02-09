#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import bz2
import heapq
import lzma
import re
import zlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

MAGIC = b"MC"
VERSION = 1
DICT_ID = 2

MODE_BYTE_DICT = 0
MODE_FIXED_BITS = 1
MODE_DEFLATE = 2
MODE_ZLIB = 3
MODE_BZ2 = 4
MODE_LZMA = 5
# NLP profile mode ids are wire-level aliases; encode/decode stays dependency-free.
MODE_NLTK = 6
MODE_SPACY = 7
MODE_TENSORFLOW = 8
SUPPORTED_MODES = (
    MODE_BYTE_DICT,
    MODE_FIXED_BITS,
    MODE_DEFLATE,
    MODE_ZLIB,
    MODE_BZ2,
    MODE_LZMA,
    MODE_NLTK,
    MODE_SPACY,
    MODE_TENSORFLOW,
)
MODE_TO_NAME: Dict[int, str] = {
    MODE_BYTE_DICT: "mc_byte_dict",
    MODE_FIXED_BITS: "mc_fixed_bits",
    MODE_DEFLATE: "mc_deflate",
    MODE_ZLIB: "mc_zlib",
    MODE_BZ2: "mc_bz2",
    MODE_LZMA: "mc_lzma",
    MODE_NLTK: "mc_nltk",
    MODE_SPACY: "mc_spacy",
    MODE_TENSORFLOW: "mc_tensorflow",
}

FLAG_LOWERCASE_USED = 1 << 0
FLAG_PRESERVE_CASE = 1 << 1
FLAG_PUNCT_TOKENS_ENABLED = 1 << 2
FLAG_EXACT_TEXT = 1 << 3

ESCAPE_BYTE = 0xFF
MAX_ESCAPE_TOKEN_BYTES = 64

PUNCT_TOKENS = (".", ",", "!", "?", "-", ":", ";", "(", ")", '"', "'", "—", "/", "«", "»")
PUNCT_SET = set(PUNCT_TOKENS)
OPEN_PUNCT_NO_SPACE_AFTER = {"(", '"', "'", "«"}

DEFAULT_PHRASES = [
    "каждый участник сети",
    "в течение дня",
    "в случае, если",
    "в идеале",
    "своими наработками",
    "полезных инструментов",
    "экспериментальных решений",
    "исходный код",
    "описание и ссылку",
    "опубликовать только ссылку",
    "отправлено в",
    "доставлено в",
    "получено в",
    "с 1 попытки",
    "с 2 попытки",
    "с 3 попытки",
    "хопы туда",
    "хопы обратно",
    "частей 1/1",
    "частей 1/2",
    "частей 1/3",
    "частей 2/3",
    "частей 3/3",
    "в процессе",
    "начали прием",
]


class CompressionError(ValueError):
    pass


class CompressionFormatError(CompressionError):
    pass


class CompressionCRCError(CompressionError):
    pass


def _crc8(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc & 0xFF


def _varint_encode(value: int) -> bytes:
    if value < 0:
        raise CompressionError("negative varint is not supported")
    out = bytearray()
    v = int(value)
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _varint_decode(data: bytes, offset: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 35:
            break
    raise CompressionFormatError("invalid varint")


def _tokenize_basic(text: str, preserve_case: bool = False) -> List[str]:
    tokens: List[str] = []
    buf: List[str] = []
    for ch in text:
        if ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf.clear()
            tokens.append(ch)
            continue
        if ch in PUNCT_SET:
            if buf:
                tokens.append("".join(buf))
                buf.clear()
            tokens.append(ch)
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    if not preserve_case:
        lowered: List[str] = []
        for t in tokens:
            if t in PUNCT_SET or t.isspace():
                lowered.append(t)
            else:
                lowered.append(t.lower())
        return lowered
    return tokens


def _merge_phrase_tokens(tokens: Sequence[str], preserve_case: bool) -> List[str]:
    if not tokens:
        return []
    phrase_map = PHRASE_SEQ_TO_TOKEN_CS if preserve_case else PHRASE_SEQ_TO_TOKEN_LOWER
    max_len = PHRASE_MAX_LEN_CS if preserve_case else PHRASE_MAX_LEN_LOWER
    if not phrase_map or max_len < 2:
        return list(tokens)
    out: List[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        matched = None
        matched_len = 0
        max_probe = min(max_len, n - i)
        for length in range(max_probe, 1, -1):
            seq = tuple(tokens[i : i + length])
            tok = phrase_map.get(seq)
            if tok is not None:
                matched = tok
                matched_len = length
                break
        if matched is not None:
            out.append(matched)
            i += matched_len
        else:
            out.append(tokens[i])
            i += 1
    return out


def _tokenize(text: str, preserve_case: bool = False) -> List[str]:
    base = _tokenize_basic(text, preserve_case=preserve_case)
    return _merge_phrase_tokens(base, preserve_case=preserve_case)


def _detokenize(tokens: Sequence[str]) -> str:
    if not tokens:
        return ""
    out: List[str] = []
    prev = None
    for tok in tokens:
        if not tok:
            continue
        if prev is None:
            out.append(tok)
            prev = tok
            continue
        need_space = True
        if tok in PUNCT_SET:
            need_space = False
        elif prev in OPEN_PUNCT_NO_SPACE_AFTER:
            need_space = False
        elif prev == "-":
            need_space = False
        if need_space:
            out.append(" ")
        out.append(tok)
        prev = tok
    return "".join(out)


def _build_default_dict_tokens() -> List[str]:
    words = [
        "и", "в", "не", "на", "я", "быть", "он", "с", "что", "а", "по", "это", "она", "к", "но", "они",
        "мы", "как", "из", "у", "же", "за", "ты", "от", "то", "о", "так", "его", "для", "все", "вы", "да",
        "нет", "если", "или", "когда", "только", "еще", "уже", "очень", "можно", "нужно", "тут", "там",
        "где", "кто", "чтобы", "почему", "потом", "сейчас", "привет", "ок", "хорошо", "спасибо", "давай",
        "сообщение", "сообщения", "текст", "ключ", "ключи", "доставка", "попытка", "попытки", "пакет",
        "пакеты", "часть", "части", "хоп", "хопы", "время", "минута", "секунда", "статус", "ошибка",
        "получено", "доставлено", "отправлено", "прием", "принимаю", "отправка", "очередь", "сеть", "узел",
        "нода", "порт", "канал", "настройки", "лог", "история", "контакт", "диалог", "группа", "поиск",
        "проверка", "тест", "работает", "нормально", "да", "нет", "может", "будет", "сделать", "сделай",
        "надо", "можно", "нельзя", "пока", "потом", "снова", "сразу", "длинное", "короткое", "имя", "id",
        "public", "pub", "ack", "mesh", "lora", "node", "message", "send", "recv", "queue", "radio", "gui",
        "error", "timeout", "retry", "config", "history", "runtime", "clear", "delete", "request", "response",
        "exchange", "encryption", "active", "waiting", "ready", "connected", "disconnected", "self", "peer",
        "part", "parts", "done", "in", "at", "elapsed", "hops", "there", "back", "delivered", "received",
        "sent", "start", "stop", "mode", "byte", "fixed", "dict", "compression", "enabled", "disabled",
        "русский", "английский", "принято", "отправил", "получил", "перезапуск", "профиль", "инициализация",
        "обнаружение", "broadcast", "многопакетный", "однопакетный", "динамический", "таймер", "оранжевый",
        "замок", "прочитано", "непрочитано", "копировать", "буфер", "подтверждение", "регенерация",
        "совместимость", "протокол", "формат", "данные", "байт", "бит", "словарь", "токен", "пунктуация",
        "скобка", "кавычка", "длина", "crc", "версия", "магия", "режим",
    ]
    # Chat/feed-oriented words often seen in public mesh discussions.
    words.extend([
        "каждый", "может", "поделиться", "здесь", "своими", "наработками", "полезных", "инструментов",
        "экспериментальных", "решений", "выкладывать", "ваш", "проект", "созданный", "нуля", "форк",
        "чужого", "доработками", "автор", "ссылку", "отправляйте", "топик", "ссылки", "зовите", "сам",
        "написал", "творение", "случае", "закрытый", "описание", "сервис", "исходный", "идеале",
        "разместить", "github", "gitflic", "gitverse", "аналоге", "опубликовать", "часть", "частей",
        "частями", "начали", "прием", "получено", "доставлено", "отправлено", "прошло", "попытки",
        "попытка", "хопов", "туда", "обратно", "минута", "секунда", "включено", "выключено",
    ])
    tokens: List[str] = list(PUNCT_TOKENS) + [" ", "\n", "\t"]
    seen = set(tokens)
    for p in DEFAULT_PHRASES:
        if p not in seen:
            tokens.append(p)
            seen.add(p)
        if len(tokens) >= 255:
            break
    for w in words:
        if w not in seen:
            tokens.append(w)
            seen.add(w)
        if len(tokens) >= 255:
            break
    # Preserve-case mode benefits from title-case dictionary entries.
    if len(tokens) < 255:
        for w in words:
            if not w or w in PUNCT_SET or w.isspace() or not w[0].isalpha():
                continue
            cap = w[0].upper() + w[1:]
            if cap not in seen:
                tokens.append(cap)
                seen.add(cap)
            if len(tokens) >= 255:
                break
    return tokens[:255]


DICT_TOKENS: List[str] = _build_default_dict_tokens()
TOKEN_TO_INDEX: Dict[str, int] = {t: i for i, t in enumerate(DICT_TOKENS)}
ESC_SYMBOL = len(DICT_TOKENS)


def _build_phrase_maps() -> Tuple[Dict[Tuple[str, ...], str], Dict[Tuple[str, ...], str], int, int]:
    cs: Dict[Tuple[str, ...], str] = {}
    lower: Dict[Tuple[str, ...], str] = {}
    max_cs = 0
    max_lower = 0
    for tok in DICT_TOKENS:
        if " " not in tok:
            continue
        seq_cs = tuple(_tokenize_basic(tok, preserve_case=True))
        if len(seq_cs) < 2:
            continue
        if "".join(seq_cs) != tok:
            continue
        cs[seq_cs] = tok
        if len(seq_cs) > max_cs:
            max_cs = len(seq_cs)
        seq_lower = tuple(_tokenize_basic(tok, preserve_case=False))
        tok_lower = tok.lower()
        if tok_lower in TOKEN_TO_INDEX:
            lower[seq_lower] = tok_lower
        else:
            lower[seq_lower] = tok
        if len(seq_lower) > max_lower:
            max_lower = len(seq_lower)
    return cs, lower, max_cs, max_lower


PHRASE_SEQ_TO_TOKEN_CS, PHRASE_SEQ_TO_TOKEN_LOWER, PHRASE_MAX_LEN_CS, PHRASE_MAX_LEN_LOWER = _build_phrase_maps()


@dataclass
class _HuffmanCodebook:
    sym_to_code: Dict[int, Tuple[int, int]]
    tree: Dict[int, object]


def _build_huffman_codebook(num_symbols: int) -> _HuffmanCodebook:
    # Static deterministic frequencies by rank: lower symbol id = more frequent.
    freqs = [max(1, num_symbols - i) for i in range(num_symbols)]
    heap: List[Tuple[int, int, object]] = []
    order = 0
    for sym, f in enumerate(freqs):
        heapq.heappush(heap, (f, order, sym))
        order += 1
    while len(heap) > 1:
        f1, _o1, n1 = heapq.heappop(heap)
        f2, _o2, n2 = heapq.heappop(heap)
        node = (n1, n2)
        heapq.heappush(heap, (f1 + f2, order, node))
        order += 1
    _f, _o, root = heap[0]
    lengths: Dict[int, int] = {}

    def walk(node: object, depth: int) -> None:
        if isinstance(node, int):
            lengths[node] = max(1, depth)
            return
        left, right = node
        walk(left, depth + 1)
        walk(right, depth + 1)

    walk(root, 0)

    by_len = sorted(((l, s) for s, l in lengths.items()), key=lambda x: (x[0], x[1]))
    code = 0
    prev_len = by_len[0][0]
    sym_to_code: Dict[int, Tuple[int, int]] = {}
    for length, sym in by_len:
        code <<= (length - prev_len)
        sym_to_code[sym] = (code, length)
        code += 1
        prev_len = length

    tree: Dict[int, object] = {}
    for sym, (c, clen) in sym_to_code.items():
        node = tree
        for i in range(clen - 1, -1, -1):
            bit = (c >> i) & 1
            if i == 0:
                node[bit] = sym
            else:
                nxt = node.get(bit)
                if not isinstance(nxt, dict):
                    nxt = {}
                    node[bit] = nxt
                node = nxt
    return _HuffmanCodebook(sym_to_code=sym_to_code, tree=tree)


HUF = _build_huffman_codebook(len(DICT_TOKENS) + 1)


class _BitWriter:
    def __init__(self) -> None:
        self._buf = bytearray()
        self._acc = 0
        self._bits = 0

    def write(self, code: int, length: int) -> None:
        self._acc = (self._acc << length) | (code & ((1 << length) - 1))
        self._bits += length
        while self._bits >= 8:
            shift = self._bits - 8
            self._buf.append((self._acc >> shift) & 0xFF)
            self._acc &= (1 << shift) - 1
            self._bits -= 8

    def to_bytes(self) -> bytes:
        out = bytearray(self._buf)
        if self._bits:
            out.append((self._acc << (8 - self._bits)) & 0xFF)
        return bytes(out)


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self._bit = 0

    def read_bit(self) -> int:
        if self._pos >= len(self._data):
            raise CompressionFormatError("unexpected end of bitstream")
        b = self._data[self._pos]
        bit = (b >> (7 - self._bit)) & 1
        self._bit += 1
        if self._bit >= 8:
            self._bit = 0
            self._pos += 1
        return bit


def _encode_byte_dict(tokens: Sequence[str]) -> bytes:
    out = bytearray()
    out.extend(_varint_encode(len(tokens)))
    for tok in tokens:
        idx = TOKEN_TO_INDEX.get(tok)
        if idx is not None:
            out.append(idx)
            continue
        raw = tok.encode("utf-8")
        if len(raw) > MAX_ESCAPE_TOKEN_BYTES:
            raise CompressionError(f"token too long for escape (> {MAX_ESCAPE_TOKEN_BYTES} bytes)")
        out.append(ESCAPE_BYTE)
        out.extend(_varint_encode(len(raw)))
        out.extend(raw)
    return bytes(out)


def _decode_byte_dict(data: bytes) -> List[str]:
    pos = 0
    token_count, pos = _varint_decode(data, pos)
    tokens: List[str] = []
    for _ in range(token_count):
        if pos >= len(data):
            raise CompressionFormatError("unexpected end of BYTE_DICT data")
        b = data[pos]
        pos += 1
        if b != ESCAPE_BYTE:
            if b >= len(DICT_TOKENS):
                raise CompressionFormatError(f"invalid dictionary index: {b}")
            tokens.append(DICT_TOKENS[b])
            continue
        raw_len, pos = _varint_decode(data, pos)
        if raw_len > MAX_ESCAPE_TOKEN_BYTES:
            raise CompressionFormatError(f"escape token too long: {raw_len}")
        end = pos + raw_len
        if end > len(data):
            raise CompressionFormatError("truncated escape token payload")
        raw = data[pos:end]
        pos = end
        tokens.append(raw.decode("utf-8", errors="strict"))
    if pos != len(data):
        raise CompressionFormatError("trailing bytes in BYTE_DICT data")
    return tokens


def _encode_fixed(tokens: Sequence[str]) -> bytes:
    symbols: List[int] = []
    esc_raw: List[bytes] = []
    for tok in tokens:
        idx = TOKEN_TO_INDEX.get(tok)
        if idx is not None:
            symbols.append(idx)
            continue
        raw = tok.encode("utf-8")
        if len(raw) > MAX_ESCAPE_TOKEN_BYTES:
            raise CompressionError(f"token too long for escape (> {MAX_ESCAPE_TOKEN_BYTES} bytes)")
        symbols.append(ESC_SYMBOL)
        esc_raw.append(raw)

    bw = _BitWriter()
    for sym in symbols:
        code, clen = HUF.sym_to_code[sym]
        bw.write(code, clen)
    bits = bw.to_bytes()

    out = bytearray()
    out.extend(_varint_encode(len(symbols)))
    out.extend(_varint_encode(len(esc_raw)))
    out.extend(_varint_encode(len(bits)))
    out.extend(bits)
    for raw in esc_raw:
        out.extend(_varint_encode(len(raw)))
        out.extend(raw)
    return bytes(out)


def _encode_binary(text: str, mode: int, preserve_case: bool) -> bytes:
    source = text if preserve_case else text.lower()
    raw = source.encode("utf-8")
    if mode in (MODE_DEFLATE, MODE_NLTK):
        cobj = zlib.compressobj(level=9, wbits=-15)
        return cobj.compress(raw) + cobj.flush()
    if mode in (MODE_ZLIB, MODE_SPACY):
        return zlib.compress(raw, level=9)
    if mode == MODE_BZ2:
        return bz2.compress(raw, compresslevel=9)
    if mode in (MODE_LZMA, MODE_TENSORFLOW):
        return lzma.compress(raw, preset=9)
    raise CompressionError(f"unsupported binary compression mode: {mode}")


def _decode_binary(data: bytes, mode: int) -> str:
    if mode in (MODE_DEFLATE, MODE_NLTK):
        raw = zlib.decompress(data, wbits=-15)
    elif mode in (MODE_ZLIB, MODE_SPACY):
        raw = zlib.decompress(data)
    elif mode == MODE_BZ2:
        raw = bz2.decompress(data)
    elif mode in (MODE_LZMA, MODE_TENSORFLOW):
        raw = lzma.decompress(data)
    else:
        raise CompressionFormatError(f"unsupported binary compression mode: {mode}")
    return raw.decode("utf-8", errors="strict")


def mode_name(mode: int) -> str:
    return MODE_TO_NAME.get(int(mode), "mc_unknown")


def _decode_fixed(data: bytes) -> List[str]:
    pos = 0
    token_count, pos = _varint_decode(data, pos)
    esc_count, pos = _varint_decode(data, pos)
    bit_len, pos = _varint_decode(data, pos)
    end_bits = pos + bit_len
    if end_bits > len(data):
        raise CompressionFormatError("truncated FIXED bitstream")
    bits = data[pos:end_bits]
    pos = end_bits

    br = _BitReader(bits)
    symbols: List[int] = []
    esc_seen = 0
    for _ in range(token_count):
        node: object = HUF.tree
        while isinstance(node, dict):
            bit = br.read_bit()
            if bit not in node:
                raise CompressionFormatError("invalid huffman code")
            node = node[bit]
        sym = int(node)
        symbols.append(sym)
        if sym == ESC_SYMBOL:
            esc_seen += 1
    if esc_seen != esc_count:
        raise CompressionFormatError("escape count mismatch in FIXED data")

    esc_payloads: List[str] = []
    for _ in range(esc_count):
        raw_len, pos = _varint_decode(data, pos)
        if raw_len > MAX_ESCAPE_TOKEN_BYTES:
            raise CompressionFormatError(f"escape token too long: {raw_len}")
        end = pos + raw_len
        if end > len(data):
            raise CompressionFormatError("truncated FIXED escape payload")
        esc_payloads.append(data[pos:end].decode("utf-8", errors="strict"))
        pos = end
    if pos != len(data):
        raise CompressionFormatError("trailing bytes in FIXED data")

    tokens: List[str] = []
    esc_idx = 0
    for sym in symbols:
        if sym == ESC_SYMBOL:
            tokens.append(esc_payloads[esc_idx])
            esc_idx += 1
        else:
            if sym < 0 or sym >= len(DICT_TOKENS):
                raise CompressionFormatError(f"invalid dictionary symbol: {sym}")
            tokens.append(DICT_TOKENS[sym])
    return tokens


def compress_text(text: str, mode: int = MODE_BYTE_DICT, preserve_case: bool = False) -> bytes:
    if not isinstance(text, str):
        raise CompressionError("text must be str")
    tokens = _tokenize(text, preserve_case=preserve_case)
    if mode == MODE_BYTE_DICT:
        data = _encode_byte_dict(tokens)
    elif mode == MODE_FIXED_BITS:
        data = _encode_fixed(tokens)
    elif mode in (
        MODE_DEFLATE,
        MODE_ZLIB,
        MODE_BZ2,
        MODE_LZMA,
        MODE_NLTK,
        MODE_SPACY,
        MODE_TENSORFLOW,
    ):
        data = _encode_binary(text, mode, preserve_case=preserve_case)
    else:
        raise CompressionError(f"unsupported compression mode: {mode}")

    flags = FLAG_PUNCT_TOKENS_ENABLED | FLAG_EXACT_TEXT
    if not preserve_case:
        flags |= FLAG_LOWERCASE_USED
    if preserve_case:
        flags |= FLAG_PRESERVE_CASE

    header = bytes([MAGIC[0], MAGIC[1], VERSION, mode & 0xFF, DICT_ID & 0xFF, flags & 0xFF])
    crc = _crc8(header + data)
    return header + data + bytes([crc])


def decompress_text(blob: bytes) -> str:
    if not isinstance(blob, (bytes, bytearray)):
        raise CompressionFormatError("blob must be bytes")
    raw = bytes(blob)
    if len(raw) < 7:
        raise CompressionFormatError("compressed block too short")
    if raw[:2] != MAGIC:
        raise CompressionFormatError("invalid MAGIC")
    ver = raw[2]
    if ver != VERSION:
        raise CompressionFormatError(f"unsupported version: {ver}")
    mode = raw[3]
    dict_id = raw[4]
    if dict_id != DICT_ID:
        raise CompressionFormatError(f"unsupported dictionary id: {dict_id}")
    # flags currently not required for decode path, but kept for forward checks.
    flags = raw[5]
    data = raw[6:-1]
    crc = raw[-1]
    if _crc8(raw[:-1]) != crc:
        raise CompressionCRCError("CRC8 mismatch")

    if mode == MODE_BYTE_DICT:
        tokens = _decode_byte_dict(data)
    elif mode == MODE_FIXED_BITS:
        tokens = _decode_fixed(data)
    elif mode in (
        MODE_DEFLATE,
        MODE_ZLIB,
        MODE_BZ2,
        MODE_LZMA,
        MODE_NLTK,
        MODE_SPACY,
        MODE_TENSORFLOW,
    ):
        return _decode_binary(data, mode)
    else:
        raise CompressionFormatError(f"unsupported mode: {mode}")
    if flags & FLAG_EXACT_TEXT:
        return "".join(tokens)
    return _detokenize(tokens)


def should_compress(
    text: str,
    mode: int = MODE_BYTE_DICT,
    min_gain_bytes: int = 2,
    preserve_case: bool = False,
) -> bool:
    plain = text.encode("utf-8")
    if not plain:
        return False
    try:
        comp = compress_text(text, mode=mode, preserve_case=preserve_case)
    except CompressionError:
        return False
    return len(comp) < (len(plain) - int(min_gain_bytes))
