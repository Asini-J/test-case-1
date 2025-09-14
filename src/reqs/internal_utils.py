import re
from .compat import builtin_str

# Regex patterns for validating header names and values
HEADER_NAME_PATTERN_BYTES = re.compile(rb"^[^:\s][^:\r\n]*$")
HEADER_NAME_PATTERN_STR = re.compile(r"^[^:\s][^:\r\n]*$")
HEADER_VALUE_PATTERN_BYTES = re.compile(rb"^\S[^\r\n]*$|^$")
HEADER_VALUE_PATTERN_STR = re.compile(r"^\S[^\r\n]*$|^$")

# Validators grouped by string type
STRING_HEADER_VALIDATORS = (HEADER_NAME_PATTERN_STR, HEADER_VALUE_PATTERN_STR)
BYTE_HEADER_VALIDATORS = (HEADER_NAME_PATTERN_BYTES, HEADER_VALUE_PATTERN_BYTES)

HEADER_VALIDATORS = {
    bytes: BYTE_HEADER_VALIDATORS,
    str: STRING_HEADER_VALIDATORS,
}


def to_native_string(value, encoding="ascii"):
    """
    Convert a string-like object into the system's native string type.
    Decodes byte strings using the given encoding (default: ASCII).
    
    :param value: The input string (bytes or str).
    :param encoding: Encoding to use when decoding bytes.
    :return: Native Python string.
    """
    if isinstance(value, builtin_str):
        return value
    return value.decode(encoding)


def is_ascii_only(text):
    """
    Check if a given string contains only ASCII characters.
    
    :param text: Unicode string to check.
    :return: True if ASCII-only, False otherwise.
    """
    assert isinstance(text, str), "Input must be a string."
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False
