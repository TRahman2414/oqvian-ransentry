from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = PROJECT_ROOT / "demo_workspace" / "monitored_files"
MARKER = ".ransentry-root"
MARKER_VALUE = "OQVIAN RANSENTRY disposable demo workspace v1"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 500


class UnsafeDemoRoot(RuntimeError):
    pass


def verify_demo_root() -> Path:
    if DEMO_ROOT.is_symlink() or not DEMO_ROOT.is_dir():
        raise UnsafeDemoRoot("Demo root is missing or is a symbolic link; refusing filesystem access.")
    canonical = DEMO_ROOT.resolve(strict=True)
    expected = (PROJECT_ROOT / "demo_workspace" / "monitored_files").resolve(strict=True)
    if canonical != expected:
        raise UnsafeDemoRoot("Demo root identity changed; refusing filesystem access.")
    marker = DEMO_ROOT / MARKER
    try:
        marker_fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            marker_stat = os.fstat(marker_fd)
            marker_value = os.read(marker_fd, 256).decode("utf-8").strip()
        finally:
            os.close(marker_fd)
    except OSError as exc:
        raise UnsafeDemoRoot("Safety marker is missing or invalid; refusing filesystem access.") from exc
    if not stat.S_ISREG(marker_stat.st_mode) or marker_value != MARKER_VALUE:
        raise UnsafeDemoRoot("Safety marker is missing or invalid; refusing filesystem access.")
    return canonical


def checked_path(relative_path: str) -> Path:
    root = verify_demo_root()
    candidate_rel = Path(relative_path)
    if candidate_rel.is_absolute() or not candidate_rel.parts or any(part in {"..", "."} for part in candidate_rel.parts):
        raise UnsafeDemoRoot("Path is not a valid demo-relative path.")
    if MARKER in candidate_rel.parts:
        raise UnsafeDemoRoot("Safety marker is not a demo fixture.")
    current = root
    for part in candidate_rel.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafeDemoRoot("Symbolic links are not permitted in the demo workspace.")
    resolved = current.resolve(strict=False)
    if os.path.commonpath((str(root), str(resolved))) != str(root):
        raise UnsafeDemoRoot("Path escapes the demo workspace.")
    return current


def iter_regular_files() -> list[Path]:
    root = verify_demo_root()
    result: list[Path] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
        for name in names:
            path = Path(current) / name
            if path.name == MARKER:
                continue
            if path.is_symlink():
                continue
            try:
                info = path.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                result.append(path)
                if len(result) > MAX_FILES:
                    raise UnsafeDemoRoot("Demo workspace file-count limit exceeded.")
    return result


def sha256_file(path: Path) -> tuple[str, os.stat_result]:
    root = verify_demo_root()
    if path.is_symlink() or os.path.commonpath((str(root), str(path.resolve(strict=True)))) != str(root):
        raise UnsafeDemoRoot("Unsafe file path during integrity read.")
    relative = path.relative_to(root).as_posix()
    fd = open_demo_fd(relative, os.O_RDONLY)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
        os.close(fd)
        raise UnsafeDemoRoot("File type or size is outside demo integrity limits.")
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
    finally:
        after = os.fstat(fd)
        os.close(fd)
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise UnsafeDemoRoot("File changed while it was being hashed; retry verification.")
    return digest.hexdigest(), after


def _open_parent(relative_path: str) -> tuple[int, str]:
    root = verify_demo_root()
    rel = Path(relative_path)
    if rel.is_absolute() or not rel.parts or any(part in {"..", "."} for part in rel.parts):
        raise UnsafeDemoRoot("Path is not a valid demo-relative path.")
    if rel.name == MARKER:
        raise UnsafeDemoRoot("Safety marker is not a demo fixture.")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open(root, directory_flags)
    try:
        for part in rel.parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd, rel.name
    except Exception:
        os.close(current_fd)
        raise UnsafeDemoRoot("Unsafe or unavailable parent directory in demo path.")


def open_demo_fd(relative_path: str, flags: int) -> int:
    parent_fd, name = _open_parent(relative_path)
    try:
        return os.open(name, flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeDemoRoot("Demo file is missing, unsafe, or unavailable.") from exc
    finally:
        os.close(parent_fd)


def write_demo_file(relative_path: str, content: str, *, create: bool = False, append: bool = False) -> None:
    flags = os.O_WRONLY
    if create:
        flags |= os.O_CREAT | os.O_TRUNC
    elif append:
        flags |= os.O_APPEND
    fd = open_demo_fd(relative_path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise UnsafeDemoRoot("Demo file type or size is outside write limits.")
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
            stream.write(content)
    finally:
        os.close(fd)


def rename_demo_file(source: str, destination: str) -> None:
    source_fd, source_name = _open_parent(source)
    try:
        destination_fd, destination_name = _open_parent(destination)
        try:
            info = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeDemoRoot("Only regular demo fixtures may be renamed.")
            try:
                os.stat(destination_name, dir_fd=destination_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise UnsafeDemoRoot("Destination already exists.")
            os.rename(source_name, destination_name, src_dir_fd=source_fd, dst_dir_fd=destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def unlink_demo_file(relative_path: str) -> None:
    parent_fd, name = _open_parent(relative_path)
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeDemoRoot("Only regular demo fixtures may be removed.")
        os.unlink(name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)

