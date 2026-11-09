# MayakVPN 5.1.0.14 source package

This package starts from the accepted 5.1.0.13 GPL source archive (SHA-256 f05543047c67cff1f7ab5734a1778c9e8362378ad0f10fa1536e5d50346d5684) and overlays exactly the seven reviewed updater/UI source files listed in `SOURCE_PROVENANCE.txt`, as approved by the final 5.1.0.14 review manifest. The accepted 68-file visual baseline is verified against the base archive and retained unchanged. No other mutable working-tree files are included. Existing GPL/OFL and third-party notices and dependency sources are retained. This archive contains source, not a built or signed binary.

## Build notes

See `RELEASE_BUILD_NOTES_5.1.0.14.md` and the upstream build instructions. SDKs, Qt/MSVC, Conan dependencies, IFW, and host tools remain external; this is not a reproducible toolchain.

`SOURCE_MANIFEST.sha256` hashes each payload except itself. `SOURCE_PROVENANCE.txt` records the immutable base, review manifest, and exact approved delta.
