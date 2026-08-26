"""Splitting documents into embeddable chunks along natural boundaries
-- a whole MITRE technique, a whole markdown section -- rather than
blind character-count slicing.

Why this matters: an embedding compresses everything fed into it into
ONE fixed-size vector. A chunk that mixes several unrelated ideas
produces a blurry, averaged vector that won't closely match a query
about any single one of those ideas. Keeping each chunk to roughly one
coherent idea is what makes retrieval actually find the right thing.

Overlap exists to protect against an *arbitrary* cut point severing a
sentence's meaning. When a chunk boundary is already natural (a whole
technique, a whole section), overlap matters far less -- it only earns
its keep here in the fallback path, when a single section is too long
and has to be sub-split.
"""

import re

MAX_CHARS = 1200
OVERLAP_CHARS = 150

_HEADER_RE = re.compile(r"^(#{2,3})\s+(.*)")


def split_by_markdown_headers(text: str) -> list[tuple[str, str]]:
    """Splits markdown text at ## or ### headers.

    Returns a list of (header_title, section_body) tuples, in document
    order. Content before the first header (if any) is dropped only if
    empty; a document with no headers at all comes back as a single
    ("", full_text) tuple.
    """
    lines = text.split("\n")
    sections: list[tuple[str, str]] = []
    current_title = ""
    current_lines: list[str] = []

    for line in lines:
        match = _HEADER_RE.match(line)
        if match:
            if current_lines:
                sections.append((current_title, "\n".join(current_lines).strip()))
            current_title = match.group(2).strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_lines:
        sections.append((current_title, "\n".join(current_lines).strip()))

    sections = [(title, body) for title, body in sections if body]
    return sections or [("", text.strip())]


def split_long_text(text: str, max_chars: int = MAX_CHARS, overlap: int = OVERLAP_CHARS) -> list[str]:
    """Splits text into pieces no longer than max_chars, breaking at
    paragraph boundaries wherever possible. Returns [text] unchanged
    (no split at all) if it already fits -- this is the common case for
    MITRE technique descriptions and most markdown sections.
    """
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]

    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    current = ""

    for para in paragraphs:
        if len(para) > max_chars:
            # Rare: a single paragraph alone exceeds the ceiling. Hard
            # character-split it, carrying overlap forward at each cut.
            if current:
                chunks.append(current)
                current = ""
            start = 0
            while start < len(para):
                chunks.append(para[start:start + max_chars])
                start += max_chars - overlap
            continue

        candidate = f"{current}\n\n{para}" if current else para
        if len(candidate) <= max_chars:
            current = candidate
        else:
            chunks.append(current)
            tail = current[-overlap:] if len(current) > overlap else current
            current = f"{tail}\n\n{para}"

    if current:
        chunks.append(current)

    return chunks


def chunk_markdown(text: str) -> list[dict]:
    """A markdown document -> chunks along its own header boundaries,
    sub-splitting only sections that exceed the size ceiling.

    Returns [{"section": str, "text": str}, ...] in document order.
    """
    chunks = []
    for title, body in split_by_markdown_headers(text):
        for piece in split_long_text(body):
            chunks.append({"section": title, "text": piece})
    return chunks
