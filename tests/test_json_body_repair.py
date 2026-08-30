"""Unit tests for JSON body repair functionality."""

import pytest

from app.core.json_body_repair import repair_json_body


class TestJSONBodyRepair:
    """Test suite for JSON body repair function."""

    def test_real_newlines_in_string(self):
        """Test case 1: Real newlines inside JSON string are converted to escapes."""
        # Input with real newlines inside a string (actual 0x0A bytes)
        input_body = b'{"description": "Line1\n\nLine2"}'
        expected = b'{"description": "Line1\\n\\nLine2"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_already_valid_json_preserved(self):
        """Test case 2: Already valid JSON with proper escapes is preserved."""
        # Input with already escaped newlines (backslash followed by n)
        input_body = b'{"description": "Line1\\n\\nLine2"}'
        expected = b'{"description": "Line1\\n\\nLine2"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_structural_newlines_preserved(self):
        """Test case 3: Newlines outside strings (structural formatting) are preserved."""
        # Input with structural newlines
        input_body = b'{\n  "name": "Test",\n  "description": "Hola"\n}'
        expected = b'{\n  "name": "Test",\n  "description": "Hola"\n}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_escaped_quotes_handled(self):
        """Test case 4: Escaped quotes inside strings are handled correctly."""
        # Input with escaped quotes (backslash followed by quote)
        input_body = b'{"description": "He said: \\"Hello\\""}'
        expected = b'{"description": "He said: \\"Hello\\""}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_backslashes_preserved(self):
        """Test case 5: Backslashes and valid escapes are not corrupted."""
        # Input with backslashes
        input_body = b'{"path": "C:\\\\Users\\\\test"}'
        expected = b'{"path": "C:\\\\Users\\\\test"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_crlf_in_string_converted(self):
        """Test case 6: CRLF (\r\n) inside string is converted to \n escape."""
        # Input with CRLF inside string (actual 0x0D 0x0A bytes)
        input_body = b'{"description": "Line1\r\nLine2"}'
        expected = b'{"description": "Line1\\nLine2"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_complex_json_with_multiple_fields(self):
        """Test complex JSON with multiple fields and mixed content."""
        input_body = b'''{
  "name": "Test",
  "description": "Line1
Line2",
  "episodes": 1
}'''
        expected = b'''{
  "name": "Test",
  "description": "Line1\\nLine2",
  "episodes": 1
}'''

        result = repair_json_body(input_body)
        assert result == expected

    def test_empty_body(self):
        """Test that empty body is handled correctly."""
        input_body = b''
        expected = b''

        result = repair_json_body(input_body)
        assert result == expected

    def test_no_strings_in_json(self):
        """Test JSON without string values."""
        input_body = b'{"number": 42, "bool": true}'
        expected = b'{"number": 42, "bool": true}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_nested_strings(self):
        """Test nested JSON with strings at different levels."""
        input_body = b'{"outer": {"inner": "value"}}'
        expected = b'{"outer": {"inner": "value"}}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_unicode_in_strings(self):
        """Test that Unicode characters in strings are preserved."""
        input_body = b'{"text": "H\xc3\xa9llo"}'
        expected = b'{"text": "H\xc3\xa9llo"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_standalone_cr_in_string(self):
        """Test standalone CR (\r) without LF inside string."""
        input_body = b'{"description": "Line1\rLine2"}'
        expected = b'{"description": "Line1\\nLine2"}'

        result = repair_json_body(input_body)
        assert result == expected

    @pytest.mark.asyncio
    async def test_multiple_body_calls_consistency(self):
        """Test that multiple calls to request.body() return consistent repaired body."""
        from unittest.mock import AsyncMock

        from app.core.custom_route import JSONRepairRequest

        # Create a mock scope and receive
        scope = {
            "type": "http",
            "method": "POST",
            "headers": [],
            "query_string": b"",
            "path": "/",
        }

        # Mock receive to return body with real newlines
        receive = AsyncMock()
        receive.return_value = {
            "type": "http.request",
            "body": b'{"description": "Line1\n\nLine2"}',
            "more_body": False,
        }

        # Create custom request
        request = JSONRepairRequest(scope, receive)

        # Call body() multiple times - should return consistent repaired body
        body1 = await request.body()
        body2 = await request.body()
        body3 = await request.body()

        # All calls should return the same repaired body
        assert body1 == b'{"description": "Line1\\n\\nLine2"}'
        assert body2 == b'{"description": "Line1\\n\\nLine2"}'
        assert body3 == b'{"description": "Line1\\n\\nLine2"}'

        # All should be identical
        assert body1 == body2 == body3

    def test_valid_json_escapes_preserved(self):
        """Test that valid JSON escapes continue to work correctly."""
        # Test all common JSON escapes
        input_body = b'{"text": "Line1\\nLine2\\tTab\\rReturn\\bBackspace\\fFormfeed\\/Slash"}'
        expected = b'{"text": "Line1\\nLine2\\tTab\\rReturn\\bBackspace\\fFormfeed\\/Slash"}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_empty_string(self):
        """Test that empty strings are handled correctly."""
        input_body = b'{"description": ""}'
        expected = b'{"description": ""}'

        result = repair_json_body(input_body)
        assert result == expected

    def test_nested_objects_and_arrays(self):
        """Test that nested objects and arrays are handled correctly."""
        input_body = b'{"data": {"nested": {"key": "value"}}, "array": [1, 2, 3]}'
        expected = b'{"data": {"nested": {"key": "value"}}, "array": [1, 2, 3]}'

        result = repair_json_body(input_body)
        assert result == expected
