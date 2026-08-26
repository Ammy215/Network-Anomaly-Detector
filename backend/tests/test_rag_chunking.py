from app.services.rag.chunking import chunk_markdown, split_by_markdown_headers, split_long_text


def test_split_by_markdown_headers_finds_sections():
    text = """# Title

intro text

## First section
first body

### Sub section
sub body

## Second section
second body
"""
    sections = split_by_markdown_headers(text)
    titles = [t for t, _ in sections]
    assert "First section" in titles
    assert "Sub section" in titles
    assert "Second section" in titles


def test_split_by_markdown_headers_no_headers_returns_whole_text():
    text = "just a plain paragraph, no headers at all"
    sections = split_by_markdown_headers(text)
    assert sections == [("", text)]


def test_split_long_text_returns_unchanged_when_it_fits():
    text = "short text"
    assert split_long_text(text, max_chars=1200) == [text]


def test_split_long_text_splits_at_paragraph_boundaries():
    para_a = "A" * 700
    para_b = "B" * 700
    text = f"{para_a}\n\n{para_b}"
    chunks = split_long_text(text, max_chars=1200, overlap=100)
    assert len(chunks) == 2
    assert chunks[0].strip().startswith("A")
    assert chunks[1].strip().endswith("B" * 10)
    # Overlap: the second chunk should carry some tail of the first.
    assert "A" in chunks[1]


def test_split_long_text_hard_splits_a_single_oversized_paragraph():
    para = "X" * 3000
    chunks = split_long_text(para, max_chars=1200, overlap=100)
    assert len(chunks) >= 3
    for chunk in chunks:
        assert len(chunk) <= 1200
    # Every character of the original text must still be covered.
    assert all(c == "X" for chunk in chunks for c in chunk)


def test_split_long_text_never_infinite_loops_on_pathological_input():
    """Regression guard: overlap >= max_chars would make start stop
    advancing in the hard-split loop.
    """
    para = "Y" * 5000
    chunks = split_long_text(para, max_chars=500, overlap=100)
    assert len(chunks) > 1
    assert len(chunks) < 100  # sanity bound, not an infinite loop


def test_chunk_markdown_produces_one_chunk_per_short_section():
    text = """## Alpha
short alpha body

## Beta
short beta body
"""
    chunks = chunk_markdown(text)
    assert len(chunks) == 2
    assert chunks[0]["section"] == "Alpha"
    assert chunks[1]["section"] == "Beta"


def test_chunk_markdown_subsplits_a_long_section():
    long_body = ("This is one paragraph of the section. " * 40 + "\n\n") * 3
    text = f"## Big section\n{long_body}"
    chunks = chunk_markdown(text)
    assert len(chunks) > 1
    assert all(c["section"] == "Big section" for c in chunks)
