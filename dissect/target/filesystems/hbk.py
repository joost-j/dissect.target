from __future__ import annotations

import logging
import pathlib
import stat
from typing import TYPE_CHECKING, BinaryIO

from dissect.archive import hbk

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import (
    DirEntry,
    Filesystem,
    FilesystemEntry,
)
from dissect.target.helpers import fsutil, keychain
from dissect.target.helpers.keychain import KeyType

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger(__name__)


class HbkFilesystem(Filesystem):
    """Filesystem implementation for HBK files."""

    __type__ = "hbk"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        keys = keychain.get_keys_for_provider("synology") + keychain.get_keys_without_provider()
        if not keys:
            self.hbk = hbk.HBK(fh)
        else:
            for key in keys:
                passphrase, private_key = None, None

                if key.key_type == KeyType.PASSPHRASE:
                    passphrase = key.value
                elif key.key_type == KeyType.FILE:
                    try:
                        private_key = pathlib.Path(key.value).read_bytes()
                    except FileNotFoundError as e:
                        log.debug("Private key file %s not found, skipping. Error: %s", key.value, e)
                        continue
                    except Exception as e:
                        log.debug("Unexpected error reading file %s: %s", key.value, e)
                        continue
                elif key.key_type == KeyType.RAW:
                    private_key = key.value
                else:
                    continue

                try:
                    self.hbk = hbk.HBK(fh, passphrase, private_key)
                except hbk.InvalidKeyError as e:
                    log.warning(e)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        try:
            hbk.HBK(fh)
        except EOFError:
            return False
        else:
            return True

    def get(self, path: str) -> FilesystemEntry:
        return HbkFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: hbk.VolumeEntry | None = None) -> FilesystemEntry:
        try:
            return self.hbk.get(path, node)
        except hbk.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except hbk.IsADirectoryError as e:
            raise IsADirectoryError(path) from e
        except hbk.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except hbk.Error as e:
            raise FilesystemError(path) from e


class HbkDirEntry(DirEntry):
    fs: HbkFilesystem
    entry: hbk.VolumeEntry

    def get(self) -> HbkFilesystemEntry:
        return HbkFilesystemEntry(self.fs, self.path, self.entry)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return self.entry.is_dir()

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return self.entry.is_file()

    def is_symlink(self) -> bool:
        return False

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class HbkFilesystemEntry(FilesystemEntry):
    fs: HbkFilesystem
    entry: hbk.VolumeEntry

    def get(self, path: str) -> FilesystemEntry:
        return HbkFilesystemEntry(
            self.fs,
            fsutil.join(self.path, path, alt_separator=self.fs.alt_separator),
            self.fs._get_node(path, self.entry),
        )

    def open(self) -> None:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def scandir(self) -> Iterator[HbkDirEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.entry.iterdir():
            yield HbkDirEntry(self.fs, self.path, entry.name, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_dir()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_file()

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG
        size = 0 if self.is_dir() else self.entry.size

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        st_info = [
            mode | 0o755,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            id(self.fs),
            1,
            0,
            0,
            size,
            0,
            0,
            0,
        ]

        return fsutil.stat_result(st_info)
