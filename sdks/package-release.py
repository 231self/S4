#!/usr/bin/env python3
"""Build deterministic canonical and legacy SDK release archives."""

from __future__ import annotations

import argparse
import gzip
import io
import json
from pathlib import Path
import tarfile
import tomllib
from typing import Callable

SDK_ROOT = Path(__file__).resolve().parent
REPOSITORY_URL = "https://github.com/231self/S4"
EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "node_modules",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def replace_once(data: bytes, old: str, new: str, path: str) -> bytes:
    text = data.decode()
    if text.count(old) != 1:
        raise ValueError(f"expected one {old!r} in {path}")
    return text.replace(old, new, 1).encode()


def python_metadata(project_name: str) -> Callable[[str, bytes], bytes]:
    def transform(path: str, data: bytes) -> bytes:
        if path == "pyproject.toml":
            return replace_once(
                data, 'name = "maskura_client"', f'name = "{project_name}"', path
            )
        if path == "setup.py":
            return replace_once(
                data, 'NAME = "maskura_client"', f'NAME = "{project_name}"', path
            )
        return data

    return transform


def python_legacy_metadata(path: str, data: bytes) -> bytes:
    if path == "pyproject.toml":
        return replace_once(data, 'name = "maskura_client"', 'name = "s4-client"', path)
    if path == "setup.py":
        return replace_once(data, 'NAME = "maskura_client"', 'NAME = "s4-client"', path)
    return data


def typescript_legacy_metadata(path: str, data: bytes) -> bytes:
    if path != "package.json":
        return data
    package = json.loads(data)
    if package.get("name") != "maskura-client":
        raise ValueError("expected canonical TypeScript package name maskura-client")
    package["name"] = "s4-client"
    return (json.dumps(package, indent=2) + "\n").encode()


def source_files(source: Path) -> list[Path]:
    files = []
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if source.name == "python" and relative.parts[0] == "dist":
            continue
        if path.is_symlink():
            raise ValueError(f"release archives do not permit symlinks: {path}")
        if (
            path.is_file()
            and path.suffix not in EXCLUDED_SUFFIXES
            and path.name != ".DS_Store"
        ):
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(source).as_posix())


def create_archive(
    source: Path,
    output: Path,
    transform: Callable[[str, bytes], bytes] | None = None,
) -> None:
    with output.open("wb") as raw_archive:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_archive, mtime=0
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for path in source_files(source):
                    relative = path.relative_to(source).as_posix()
                    data = path.read_bytes()
                    if transform is not None:
                        data = transform(relative, data)

                    info = tarfile.TarInfo(relative)
                    info.size = len(data)
                    info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, io.BytesIO(data))


def archive_contents(path: Path) -> tuple[set[str], dict[str, bytes]]:
    with tarfile.open(path, "r:gz") as archive:
        names = set(archive.getnames())
        files = {}
        for member in archive.getmembers():
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"could not read {member.name} from {path}")
                files[member.name] = extracted.read()
    return names, files


def validate_python_archive(path: Path, project_name: str) -> None:
    names, files = archive_contents(path)
    required = {
        "pyproject.toml",
        "setup.py",
        "maskura_client/__init__.py",
        "maskura_client/py.typed",
        "s4_client/__init__.py",
        "s4_client/py.typed",
    }
    if missing := required - names:
        raise ValueError(f"{path.name} is missing {sorted(missing)}")
    metadata = tomllib.loads(files["pyproject.toml"].decode())
    if metadata["project"]["name"] != project_name:
        raise ValueError(f"{path.name} has unexpected Python project metadata")
    if metadata["project"]["urls"]["Repository"] != REPOSITORY_URL:
        raise ValueError(f"{path.name} has an invalid repository URL")
    if f'NAME = "{project_name}"' not in files["setup.py"].decode():
        raise ValueError(f"{path.name} has inconsistent setup.py metadata")


def validate_typescript_archive(path: Path, package_name: str) -> None:
    names, files = archive_contents(path)
    required = {
        "package.json",
        "index.ts",
        "highlevel.ts",
        "dist/index.js",
        "dist/index.d.ts",
    }
    if missing := required - names:
        raise ValueError(f"{path.name} is missing {sorted(missing)}")
    package = json.loads(files["package.json"])
    if package["name"] != package_name:
        raise ValueError(f"{path.name} has unexpected TypeScript package metadata")
    if package["repository"]["url"] != f"{REPOSITORY_URL}.git":
        raise ValueError(f"{path.name} has an invalid repository URL")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    archives = {
        "maskura-python-sdk.tar.gz": (
            SDK_ROOT / "python",
            python_metadata("maskura-client"),
        ),
        "s4-python-sdk.tar.gz": (SDK_ROOT / "python", python_legacy_metadata),
        "maskura-typescript-sdk.tar.gz": (SDK_ROOT / "typescript", None),
        "s4-typescript-sdk.tar.gz": (
            SDK_ROOT / "typescript",
            typescript_legacy_metadata,
        ),
    }
    for filename, (source, transform) in archives.items():
        create_archive(source, args.output_dir / filename, transform)

    validate_python_archive(
        args.output_dir / "maskura-python-sdk.tar.gz", "maskura-client"
    )
    validate_python_archive(args.output_dir / "s4-python-sdk.tar.gz", "s4-client")
    validate_typescript_archive(
        args.output_dir / "maskura-typescript-sdk.tar.gz", "maskura-client"
    )
    validate_typescript_archive(
        args.output_dir / "s4-typescript-sdk.tar.gz", "s4-client"
    )


if __name__ == "__main__":
    main()
