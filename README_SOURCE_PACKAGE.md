# MayakVPN 5.1.0.15 source candidate

This source candidate starts from the immutable accepted 5.1.0.14 GPL source ZIP (SHA-256 c441a6170a0850de41f530a9fa74191c3fcfa9949b3d9069ec0674082ce06e8d) and overlays only the ten reviewed changed baseline files plus the eleven explicitly accepted new product files. The exact 86-file BUILD_ONLY manifest and accepted14 baseline manifest hashes are recorded in `SOURCE_PROVENANCE.txt`. Unchanged accepted14 files are retained byte for byte. No other mutable working-tree files are included. Existing GPL/OFL and third-party notices and dependency sources are retained. This is a local source candidate, not a built or signed binary.

The five bundled city photos remain original files with individual licenses recorded in `CITY_PHOTO_LICENSES.md`; those photo licenses are distinct from the client's GPL license.

## Build notes

See `RELEASE_BUILD_NOTES_5.1.0.15.md` and the upstream build instructions. SDKs, Qt/MSVC, Conan dependencies, IFW, and host tools remain external; this is not a reproducible toolchain.

`SOURCE_MANIFEST.sha256` hashes each payload except itself. `SOURCE_PROVENANCE.txt` records the immutable base, accepted manifests, independent source review evidence, and exact approved deltas.
