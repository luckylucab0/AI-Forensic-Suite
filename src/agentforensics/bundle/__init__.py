"""Read and verify evidence bundles.

The format is specified in docs/BUNDLE_FORMAT.md and written by two independent collectors.
This module is the only reader, so it is also where the format's promises are actually
checked rather than assumed: that every file listed is present, that its bytes still hash
to what the collector recorded, and that the custody chain has not been edited.

A verification that only checked the files it could find would be worthless, so a missing
file, an extra file and a changed file are three distinct findings here.
"""

from agentforensics.bundle.verify import (
    BundleError,
    Manifest,
    VerifyReport,
    decode_bundle_path,
    read_manifest,
    verify_bundle,
)

__all__ = [
    "BundleError",
    "Manifest",
    "VerifyReport",
    "decode_bundle_path",
    "read_manifest",
    "verify_bundle",
]
