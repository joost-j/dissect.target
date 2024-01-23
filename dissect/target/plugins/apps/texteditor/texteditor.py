from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import NamespacePlugin

GENERIC_TAB_CONTENTS_RECORD_FIELDS = [
    ("string", "content"),
    ("string", "content_length"),
    ("string", "filename"),
]

TexteditorTabContentRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)


class TexteditorTabPlugin(NamespacePlugin):
    __namespace__ = "texteditortab"
