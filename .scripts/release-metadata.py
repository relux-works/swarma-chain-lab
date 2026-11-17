#!/usr/bin/env python3
"""Canonical gateway archives and ASCII metadata; no signature establishes origin."""
import gzip
import hashlib
import json
import pathlib
import re
import sys
import tarfile


POLICY_ROOT = pathlib.Path(__file__).resolve().parent.parent
ARCHIVES = [f"gateway_linux_{arch}.tar.gz" for arch in ("amd64", "arm64")]


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def relative(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._+/-]+", value):
        raise ValueError("invalid-input-path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("invalid-input-path")
    return value


def table():
    value = json.loads((POLICY_ROOT / ".github/release/gateway-inputs.json").read_text(encoding="ascii"))
    if set(value) != {"product", "purpose", "targets", "inputs"} or value["product"] != "gateway" or value["purpose"] != "platform-root" or value["targets"] != ["amd64", "arm64"]:
        raise ValueError("invalid-product-table")
    rows = value["inputs"]
    if not isinstance(rows, list) or len(rows) != 3:
        raise ValueError("invalid-input-inventory")
    members = []
    go_rows = 0
    for row in rows:
        kind = row.get("kind")
        keys = {"kind", "source", "member", "mode"} | ({"package"} if kind == "go" else set())
        if set(row) != keys or kind not in ("go", "file"):
            raise ValueError("invalid-input-row")
        relative(row["source"])
        member = relative(row["member"])
        if not member.startswith("credential-gateway/") or row["mode"] != ("0755" if kind == "go" else "0644"):
            raise ValueError("invalid-input-member-or-mode")
        if kind == "go":
            package = row["package"]
            if not isinstance(package, str) or not package.startswith("./cmd/"):
                raise ValueError("invalid-command-package")
            relative(package[2:])
            go_rows += 1
        members.append(member)
    if go_rows != 1 or len(set(members)) != len(members) or any(a.startswith(b + "/") for a in members for b in members if a != b):
        raise ValueError("invalid-input-inventory")
    return value


def regular(root, name):
    current = root
    for part in pathlib.PurePosixPath(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlinked-input")
    if not current.is_file():
        raise ValueError("missing-input")
    return current


def input_rows(root):
    for row in table()["inputs"]:
        if row["kind"] == "go":
            regular(root, row["source"] + "/go.mod")
            package = root / row["source"] / row["package"][2:]
            # Refuse symlinked ancestry even when the target is an existing directory.
            regular(root, row["source"] + "/" + row["package"][2:] + "/main.go")
            if not package.is_dir():
                raise ValueError("missing-command-package")
        else:
            regular(root, row["source"])
        print("\t".join((row["kind"], row["source"], row.get("package", "-"), row["member"], row["mode"])))


def pack(root, output, epoch):
    if not epoch.isdecimal():
        raise ValueError("invalid-source-epoch")
    entries = {}
    for row in table()["inputs"]:
        member = row["member"]
        regular(root, member)
        entries[member] = int(row["mode"], 8)
        for parent in pathlib.PurePosixPath(member).parents:
            if str(parent) != ".":
                entries[str(parent)] = 0o755
    # USTAR has no variable PAX metadata; gzip has no source path or clock input.
    with output.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, mode in sorted(entries.items()):
                    path = root / name
                    info = tarfile.TarInfo(name)
                    info.mtime = int(epoch)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = mode
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = path.stat().st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)


def digest(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("missing-or-symlinked-artifact")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fragment(root, names):
    return canonical({"schema": "release-set-fragment/1", "artifacts": [
        dict({"name": name, "sha256": digest(root / name)},
             **({"purpose": "platform-root"} if name in ARCHIVES else {}))
        for name in sorted(names)]})


def run():
    mode, directory, *args = sys.argv[1:]
    root = pathlib.Path(directory)
    if mode == "inputs":
        if args:
            raise ValueError("unexpected-arguments")
        input_rows(root)
    elif mode == "pack":
        output, epoch = args
        pack(root, pathlib.Path(output), epoch)
    elif mode == "create":
        commit, version, epoch = args
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit) or version != "go1.26.8" or not epoch.isdecimal():
            raise ValueError("invalid-build-inputs")
        for name in ARCHIVES:
            digest(root / name)
        provenance = {
            "commit": commit, "go_version": version, "SOURCE_DATE_EPOCH": int(epoch),
            "product": table(),
            "archive": {"format": "ustar", "order": "sorted", "mtime": int(epoch),
                        "uid": 0, "gid": 0, "uname": "", "gname": "",
                        "directory_mode": "0755", "gzip_mtime": 0, "gzip_level": 9},
            "flags": ["-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="],
            "environment": {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": ["amd64", "arm64"],
                            "GOAMD64": "v1", "GOARM64": "v8.0", "GOEXPERIMENT": "",
                            "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off"},
        }
        (root / "provenance.json").write_bytes(canonical(provenance))
        names = ARCHIVES + ["provenance.json"]
        (root / "SHA256SUMS").write_text("".join(f"{digest(root / name)}  {name}\n" for name in sorted(names)), encoding="ascii")
        (root / "release-set.json").write_bytes(fragment(root, names + ["SHA256SUMS"]))
    elif mode == "check":
        if args:
            raise ValueError("unexpected-arguments")
        digest(root / "SHA256SUMS")
        digest(root / "release-set.json")
        names = []
        checksum_lines = []
        for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (provenance\.json|gateway_linux_(amd64|arm64)\.tar\.gz)", line)
            if not match:
                raise ValueError("invalid-checksum-entry")
            expected, name = match[1], match[2]
            if name in names:
                raise ValueError("duplicate-checksum-entry")
            if digest(root / name) != expected:
                raise ValueError("artifact-digest-mismatch")
            names.append(name)
            checksum_lines.append(f"{expected}  {name}\n")
        if set(names) != set(ARCHIVES + ["provenance.json"]):
            raise ValueError("incomplete-manifest")
        if (root / "SHA256SUMS").read_bytes() != "".join(checksum_lines).encode("ascii") or names != sorted(names):
            raise ValueError("noncanonical-checksums")
        if (root / "release-set.json").read_bytes() != fragment(root, names + ["SHA256SUMS"]):
            raise ValueError("release-set-mismatch-or-noncanonical")
    else:
        raise ValueError("unknown-mode")


if __name__ == "__main__":
    try:
        run()
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        print(f"release metadata: {error}", file=sys.stderr)
        sys.exit(1)
