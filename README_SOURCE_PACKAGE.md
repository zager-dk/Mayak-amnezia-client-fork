# MayakVPN 5.1.0.12 source package

This source candidate is the accepted 5.1.0.10 public source archive, with its root folder renamed, plus exactly seven frozen Windows tunnel source files listed in `SOURCE_PROVENANCE.txt`. Existing GPL and third-party license notices are retained. This archive contains source, not a built or signed binary.

## Build notes

Start with `mayak/BUILD.md`, `README.md`, and `README_RU.md`; see `RELEASE_BUILD_NOTES_5.1.0.12.md` for the release version override and evidence limits. SDKs, Qt/MSVC, Conan dependencies, IFW, signing inputs, and host tools remain external; this is not a reproducible toolchain.

`SOURCE_MANIFEST.sha256` hashes each payload file except itself. `SOURCE_PROVENANCE.txt` records the frozen base ZIP and exact seven-file delta.
