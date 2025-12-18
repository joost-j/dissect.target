from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.hbk import HbkFilesystem
from dissect.target.helpers import keychain
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target
import logging

log = logging.getLogger(__name__)



class HbkLoader(Loader):
    """Load Synology Hyper Backup (HBK) files.

    References:
        - TODO
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.key = None
        for key in keychain.get_keys_for_provider("synology") + keychain.get_keys_without_provider():
            if key.key_type == keychain.KeyType.PASSPHRASE:
                self.key = key.value
                break
        self.hbkfs = HbkFilesystem(path.open("rb"), key=self.key)
        self.loader = None

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".hbk"

    def map(self, target: Target) -> None:
        target.filesystems.add(self.hbkfs)
