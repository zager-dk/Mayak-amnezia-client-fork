#!/usr/bin/env python3
"""Create a Mayak signed update envelope using a locally held Ed25519 key."""

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

MAX_PACKAGE_BYTES = 512 * 1024 * 1024
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$")


def parse_utc(value: str) -> dt.datetime:
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ValueError("timestamps must use YYYY-MM-DDTHH:MM:SSZ")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=("windows-x64", "android-arm64"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release-notes", default="")
    args = parser.parse_args()

    try:
        if not VERSION_RE.fullmatch(args.version) or any(int(part) > 65535 for part in args.version.split(".")):
            raise ValueError("version must have four canonical numeric components from 0 to 65535")
        if args.version_code < 1 or args.version_code > 0xFFFFFFFF:
            raise ValueError("version code is outside the supported range")
        expires = parse_utc(args.expires_at)
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        if expires <= now:
            raise ValueError("expiry must be in the future")
        artifact = args.artifact.resolve(strict=True)
        if not artifact.is_file() or artifact.is_symlink():
            raise ValueError("artifact must be a regular, non-symlink file")
        size = artifact.stat().st_size
        if size < 1 or size > MAX_PACKAGE_BYTES:
            raise ValueError("artifact size must be between 1 byte and 512 MiB")
        suffix = ".exe" if args.platform == "windows-x64" else ".apk"
        if artifact.suffix.lower() != suffix:
            raise ValueError(f"artifact suffix must be {suffix}")
        parsed_url = urlsplit(args.url)
        package_path = parsed_url.path[len("/updates/packages/"):]
        if (parsed_url.scheme != "https" or parsed_url.hostname != "mayaklight.ru"
                or parsed_url.port not in (None, 443) or parsed_url.username or parsed_url.password
                or parsed_url.query or parsed_url.fragment or not parsed_url.path.startswith("/updates/packages/")
                or ".." in parsed_url.path or "//" in parsed_url.path or "%" in parsed_url.path
                or "\\" in parsed_url.path
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*" + re.escape(suffix), package_path)):
            raise ValueError("URL must be an HTTPS Mayak package URL with the expected extension")
        if not args.private_key.is_file():
            raise ValueError("private key path is not a file")
        if len(args.release_notes) > 10000 or "\x00" in args.release_notes:
            raise ValueError("release notes are too long or malformed")
        published = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        payload_obj = {
            "product": "mayak-vpn", "channel": "stable", "platform": args.platform,
            "version": args.version, "versionCode": args.version_code,
            "url": args.url, "size": size,
            "sha256": digest.hexdigest(),
            "publishedAt": published, "expiresAt": args.expires_at,
        }
        if args.release_notes:
            payload_obj["releaseNotes"] = args.release_notes
        payload = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="mayak-update-sign-", dir=args.output.parent) as temp:
            payload_path = Path(temp) / "payload.json"
            signature_path = Path(temp) / "signature.bin"
            payload_path.write_bytes(payload)
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(args.private_key),
                            "-in", str(payload_path), "-out", str(signature_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            envelope = {
                "schema": 1, "alg": "Ed25519",
                "payload": base64.b64encode(payload).decode("ascii"),
                "signature": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
            }
        args.output.write_bytes(json.dumps(envelope, separators=(",", ":")).encode("ascii"))
        print(f"Wrote signed update envelope: {args.output} ({size} bytes, {args.platform} {args.version})")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"sign_update_manifest: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
