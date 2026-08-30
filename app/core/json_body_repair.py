"""JSON body repair utility to fix unescaped newlines in JSON strings."""



def repair_json_body(body: bytes) -> bytes:
    """
    Repair JSON body by converting real newlines inside JSON strings to escaped newlines.

    This function processes the body byte-by-byte to distinguish between:
    - Newlines outside JSON strings (structural formatting) - preserved
    - Newlines inside JSON strings (invalid JSON) - converted to \\n escapes
    - Already escaped sequences - preserved

    Args:
        body: Raw JSON body as bytes

    Returns:
        Repaired JSON body as bytes with valid JSON escapes

    Examples:
        >>> repair_json_body(b'{"desc": "Line1\\nLine2"}')
        b'{"desc": "Line1\\nLine2"}'  # Already valid, unchanged

        >>> repair_json_body(b'{"desc": "Line1\\n\\nLine2"}')
        b'{"desc": "Line1\\n\\nLine2"}'  # Real newlines converted to escapes
    """
    if not body:
        return body

    result: list[bytes] = []
    i = 0
    in_string = False
    escape_next = False

    while i < len(body):
        byte = body[i]

        # Handle escape sequences
        if escape_next:
            # We're processing an escaped character, preserve it as-is
            result.append(bytes([byte]))
            escape_next = False
            i += 1
            continue

        # Check for backslash (start of escape sequence)
        if byte == ord(b'\\'):
            result.append(bytes([byte]))
            escape_next = True
            i += 1
            continue

        # Check for quote (string delimiter)
        if byte == ord(b'"'):
            in_string = not in_string
            result.append(bytes([byte]))
            i += 1
            continue

        # Only process newlines if we're inside a JSON string
        if in_string:
            # Handle CRLF (\r\n) - convert to single \n escape
            if byte == ord(b'\r') and i + 1 < len(body) and body[i + 1] == ord(b'\n'):
                result.append(b'\\n')
                i += 2  # Skip both \r and \n
                continue

            # Handle standalone LF (\n)
            if byte == ord(b'\n'):
                result.append(b'\\n')
                i += 1
                continue

            # Handle standalone CR (\r) without following LF
            if byte == ord(b'\r'):
                result.append(b'\\n')
                i += 1
                continue

        # All other bytes are preserved as-is
        result.append(bytes([byte]))
        i += 1

    return b''.join(result)
