from __future__ import annotations

import logging
import zlib
from typing import Iterator

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import (
    UnixUserRecord,
    WindowsUserRecord,
    create_extended_descriptor,
)
from dissect.target.plugin import arg, export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorPlugin,
)

# Thanks to @Nordgaren, @daddycocoaman, @JustArion and @ogmini for their suggestions and feedback in the PR
# thread. This really helped to figure out the last missing bits and pieces
# required for recovering text from these files.

c_def = """
struct header {
    char        magic[2]; // NP
    uint8       unk0;
    uint8       fileState; // 0 if unsaved, 1 if saved
}

struct header_saved_tab {
    uleb128     filePathLength;
    wchar       filePath[filePathLength];
    uleb128     fileSize;
    uleb128     encoding;
    uleb128     carriageReturnType;
    uleb128     timestamp; // Windows Filetime format (not unix timestamp)
    char        sha256[32];
    char        unk[6];
};

struct header_unsaved_tab {
    uint8       unk0;
    uleb128     fileSize;
    uleb128     fileSizeDuplicate;
    char        unk1;
    char        unk2;
};

struct single_data_block {
    uleb128     offset;
    uleb128     nDeleted;
    uleb128     nAdded;
    wchar       data[nAdded];
    char        unk[1];
    char        crc32[4];
};

struct multi_data_extra_header {
    char        unk[4];
    char        crc32[4];
};

struct multi_data_block {
    uleb128     offset;
    uleb128     nDeleted;
    uleb128     nAdded;
    wchar       data[nAdded];
    char        crc32[4];
};
"""

c_windowstab = cstruct()
c_windowstab.load(c_def)

WindowsNotepadTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)

WindowsNotepadTabContentRecord = create_extended_descriptor([])(
    "texteditor/windowsnotepad/tab_content", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes."""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadTabContent:
    """Windows notepad tab parser"""

    def __new__(cls, file: TargetPath, include_deleted_content=False) -> WindowsNotepadTabContentRecord:
        return cls._process_tab_file(file, include_deleted_content)

    @staticmethod
    def _process_tab_file(file: TargetPath, include_deleted_content: bool) -> WindowsNotepadTabContentRecord:
        """Parse a binary tab file and reconstruct the contents.

        Args:
            file: The binary file on disk that needs to be parsed.

        Returns:
            A TextEditorTabRecord containing information that is in the tab.
        """
        with file.open("rb") as fh:
            # Header is the same for all types
            header = c_windowstab.header(fh)

            # File can be saved, or unsaved. Depending on the file state, different header fields are present
            # Currently, no information in the header is used in the outputted records, only the contents of the tab
            tab = (
                c_windowstab.header_saved_tab(fh)
                if header.fileState == 0x01  # 0x00 is unsaved, 0x01 is saved
                else c_windowstab.header_unsaved_tab(fh)
            )

            # In the case that the file size is known up front, then this fileSize is set to a nonzero value
            # This means that the data is stored in one block
            if tab.fileSize != 0:
                # So we only parse one block
                data_entry = c_windowstab.single_data_block(fh)

                # The header (minus the magic) plus all data (including the extra byte)  is included in the checksum
                actual_crc32 = _calc_crc32(header.dumps()[3:] + tab.dumps() + data_entry.dumps()[:-4])

                if data_entry.crc32 != actual_crc32:
                    logging.warning(
                        "CRC32 mismatch in single-block file: %s (expected=%s, actual=%s)",
                        file.name,
                        data_entry.crc32.hex(),
                        actual_crc32.hex(),
                    )

                text = data_entry.data

            else:
                # Here, the fileSize is zeroed, meaning that the size is not known up front.
                # Data may be stored in multiple, variable-length blocks. This happens, for example, when several
                # additions and deletions of characters have been recorded and these changes have not been 'flushed'
                mdeh = c_windowstab.multi_data_extra_header(fh)

                # Calculate CRC32 of the header and check if it matches
                actual_header_crc32 = _calc_crc32(header.dumps()[3:] + tab.dumps() + mdeh.unk)
                if mdeh.crc32 != actual_header_crc32:
                    logging.warning(
                        "CRC32 mismatch in header of multi-block file: %s " "expected=%s, actual=%s",
                        file.name,
                        mdeh.crc32.hex(),
                        actual_header_crc32.hex(),
                    )

                # Since we don't know the size of the file up front, and offsets don't necessarily have to be in order,
                # a list is used to easily insert text at offsets
                text = []

                deleted_content = ""

                while True:
                    # Unfortunately, there is no way of determining how many blocks there are. So just try to parse
                    # until we reach EOF, after which we stop.
                    try:
                        data_entry = c_windowstab.multi_data_block(fh)
                    except EOFError:
                        break

                    # Either the nAdded is nonzero, or the nDeleted
                    if data_entry.nAdded > 0:
                        # Check the CRC32 checksum for this block
                        actual_crc32 = _calc_crc32(data_entry.dumps())
                        if data_entry.crc32 != actual_crc32:
                            logging.warning(
                                "CRC32 mismatch in multi-block file: %s " "expected=%s, actual=%s",
                                file.name,
                                data_entry.crc32.hex(),
                                actual_crc32.hex(),
                            )

                        # Insert the text at the correct offset.
                        for idx in range(data_entry.nAdded):
                            text.insert(data_entry.offset + idx, data_entry.data[idx])

                    elif data_entry.nDeleted > 0:
                        # Create a new slice. Include everything up to the offset,
                        # plus everything after the nDeleted following bytes
                        if include_deleted_content:
                            deleted_content += "".join(
                                text[data_entry.offset : data_entry.offset + data_entry.nDeleted]
                            )
                        text = text[: data_entry.offset] + text[data_entry.offset + data_entry.nDeleted :]

                # Join all the characters to reconstruct the original text
                text = "".join(text)

                if include_deleted_content:
                    text += " --- DELETED-CONTENT: "
                    text += deleted_content

        return WindowsNotepadTabContentRecord(content=text, path=file)


class WindowsNotepadPlugin(TexteditorPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    GLOB = "AppData/Local/Packages/Microsoft.WindowsNotepad_*/LocalState/TabState/*.bin"

    def __init__(self, target):
        super().__init__(target)
        self.users_tabs: list[TargetPath, UnixUserRecord | WindowsUserRecord] = []
        for user_details in self.target.user_details.all_with_home():
            for tab_file in user_details.home_path.glob(self.GLOB):
                if tab_file.name.endswith(".1.bin") or tab_file.name.endswith(".0.bin"):
                    continue

                self.users_tabs.append((tab_file, user_details.user))

    def check_compatible(self) -> None:
        if not self.users_tabs:
            raise UnsupportedPluginError("No Windows Notepad temporary tab files found")

    @arg(
        "--include-deleted-content",
        type=bool,
        default=False,
        required=False,
        help="Include deleted but recoverable content.",
    )
    @export(record=WindowsNotepadTabRecord)
    def tabs(self, include_deleted_content) -> Iterator[WindowsNotepadTabRecord]:
        """Return contents from Windows 11 temporary Notepad tabs.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            path (path): The path the content originates from.
        """
        for file, user in self.users_tabs:
            # Parse the file
            r: WindowsNotepadTabContentRecord = WindowsNotepadTabContent(file, include_deleted_content)

            # Add user- and target specific information to the content record record
            yield WindowsNotepadTabRecord(content=r.content, path=r.path, _target=self.target, _user=user)
