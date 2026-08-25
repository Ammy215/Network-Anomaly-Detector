import tempfile
from pathlib import Path

from fastapi import UploadFile

ALLOWED_EXTENSIONS = (".pcap", ".pcapng")

# First 4 bytes of the file. Classic pcap has a byte-order-dependent magic
# number (big/little endian, plus a nanosecond-resolution variant of each).
# pcapng starts every file with a Section Header Block, type 0x0A0D0D0A.
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microsecond
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microsecond
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanosecond
    b"\x0a\x0d\x0d\x0a",  # pcapng, either endianness (SHB byte-order field disambiguates later)
}


class PcapValidationError(Exception):
    """Raised when an uploaded file fails extension or signature checks."""


class PcapTooLargeError(PcapValidationError):
    """Raised when an uploaded file exceeds the configured size cap."""


def has_allowed_extension(filename: str) -> bool:
    return Path(filename or "").suffix.lower() in ALLOWED_EXTENSIONS


def save_upload_to_tempfile(upload: UploadFile, max_size_bytes: int) -> str:
    """Streams the upload to a temp file, enforcing the size cap as it goes.

    Never buffers the whole upload in memory first — a chunk read loop with
    an early abort is what makes the 50MB cap actually protective rather
    than cosmetic.
    """
    chunk_size = 1024 * 1024
    total_read = 0

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp_path = tmp.name
        while True:
            chunk = upload.file.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_size_bytes:
                tmp.close()
                Path(tmp_path).unlink(missing_ok=True)
                raise PcapTooLargeError(
                    f"File exceeds the {max_size_bytes // (1024 * 1024)}MB size cap."
                )
            tmp.write(chunk)

    if total_read == 0:
        Path(tmp_path).unlink(missing_ok=True)
        raise PcapValidationError("Uploaded file is empty.")

    return tmp_path


def verify_pcap_signature(tmp_path: str) -> None:
    """Authoritative file-type check — reads the actual magic bytes rather
    than trusting the filename extension or client-supplied Content-Type,
    either of which can be wrong or deliberately spoofed.
    """
    with open(tmp_path, "rb") as f:
        header = f.read(4)

    if header not in PCAP_MAGIC_NUMBERS:
        raise PcapValidationError(
            "File does not have a valid pcap/pcapng signature — "
            "it isn't actually a packet capture, whatever it's named."
        )
