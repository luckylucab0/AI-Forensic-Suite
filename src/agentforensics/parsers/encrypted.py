"""Open an encrypted store when the analyst supplies the key, and never guess one.

One agent in this catalogue keeps its conversations in an AES-GCM container. The key is
not the analyst's secret and not this project's to publish: it belongs to the product, it
has been written down in several public places, and a repository that shipped it would be
distributing a vendor's key for the convenience of not typing it. So the key comes in at
run time, from the person running the tool, and nothing here has a default. See ADR 0029.

The cipher is not in the standard library, so the library that has it is an optional
extra. Without it, and without a key, a file is still collected, still hashed, and
reported as an encrypted store rather than read: the case says what the file is and what
it would take to read it, which is a fact an analyst can act on.

**Why the framing is tried rather than assumed.** A container is a nonce, a ciphertext and
a tag, and where each sits is a property of the product rather than of the cipher. Nothing
published states this product's layout, and inventing one would be the kind of confident
wrongness this project exists to avoid. It does not have to be invented, because GCM
authenticates: a wrong framing fails the tag check, so trying a small set of them and
reporting which one authenticated is a verifiable reading rather than a guess. The event
records the framing that worked, so somebody else can repeat it.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

# The nonce lengths worth trying, in order. Twelve bytes is what the standard recommends
# and what every library defaults to; sixteen is what an implementation that reused a block
# size writes instead.
NONCE_LENGTHS = (12, 16)

# The tag is always sixteen bytes for GCM. Where it sits is the part that varies.
TAG_LENGTH = 16

# Bytes of header that are skipped before the nonce, in order. A container often carries a
# version or a magic number in front, and one byte or four is what that looks like.
HEADERS = (0, 1, 4)

MISSING_LIBRARY = (
    "this file is an encrypted store and the cipher for it is not installed. Install the "
    "optional extra (pip install 'agentforensics[encrypted]') and pass the key with "
    "--key to read it"
)

NO_KEY = (
    "this file is an encrypted store and no key for this agent was given, so it is "
    "recorded by size and hash rather than read. Pass one with --key <agent>=<key> to "
    "read it; the key is the product's, not the user's, and this tool ships none"
)

NOT_OPENED = (
    "this file is an encrypted store and the key that was given did not open it under any "
    "of the {tried} framings this reader tries. Either the key is not this product's, or "
    "the container's layout has changed and this reader has to learn the new one"
)


@dataclass(frozen=True, slots=True)
class Opened:
    """A container that authenticated, and how."""

    plaintext: bytes
    framing: str


def parse_key(text: str) -> bytes | None:
    """A key as the analyst typed it: hexadecimal or base64, 16, 24 or 32 bytes.

    Returns None rather than raising, because a mistyped key is an answer to give the
    analyst in the case, not an exception to abandon a collection for.
    """
    candidate = text.strip()
    for decode in (_from_hex, _from_base64):
        raw = decode(candidate)
        if raw is not None and len(raw) in (16, 24, 32):
            return raw
    return None


def _from_hex(text: str) -> bytes | None:
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _from_base64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error, ValueError:
        return None


def available() -> bool:
    """Whether the cipher is installed."""
    return _aesgcm() is not None


def _aesgcm() -> type | None:
    """The one import, kept behind a function so the package works without the extra."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    return AESGCM


def open_container(raw: bytes, key: bytes) -> Opened | None:
    """The plaintext of an AES-GCM container, under whichever framing authenticates.

    Returns None when none of them does, which is a fact about the key or the file and is
    reported as such rather than retried with anything weaker.
    """
    cipher = _aesgcm()
    if cipher is None:
        return None
    aes = cipher(key)
    for header in HEADERS:
        for nonce_length in NONCE_LENGTHS:
            if len(raw) < header + nonce_length + TAG_LENGTH:
                continue
            nonce = raw[header : header + nonce_length]
            body = raw[header + nonce_length :]
            for name, payload in _layouts(body):
                # The tag did not verify, which is the whole point of trying: a wrong
                # framing or a wrong key fails here rather than producing plausible
                # nonsense. Nothing is logged, because a failure is the expected outcome
                # of every framing but one and a log line per attempt would be noise.
                try:
                    plaintext = aes.decrypt(nonce, payload, None)
                except Exception:  # noqa: S112 - see the comment above
                    continue
                return Opened(
                    plaintext,
                    f"{header} byte header, {nonce_length} byte nonce, {name}",
                )
    return None


def _layouts(body: bytes) -> list[tuple[str, bytes]]:
    """The two places a tag sits, as the payload the library expects for each.

    The library takes the tag appended to the ciphertext, so a container that puts the tag
    in front of it is read by moving it, which is a rearrangement of the same bytes and not
    a second decryption.
    """
    if len(body) < TAG_LENGTH:
        return []
    trailing = ("tag at the end", body)
    leading = ("tag before the ciphertext", body[TAG_LENGTH:] + body[:TAG_LENGTH])
    return [trailing, leading]


def framings_tried() -> int:
    """How many layouts open_container tries, for the message it writes when none works."""
    return len(HEADERS) * len(NONCE_LENGTHS) * 2


__all__ = [
    "HEADERS",
    "MISSING_LIBRARY",
    "NONCE_LENGTHS",
    "NOT_OPENED",
    "NO_KEY",
    "TAG_LENGTH",
    "Opened",
    "available",
    "framings_tried",
    "open_container",
    "parse_key",
]
