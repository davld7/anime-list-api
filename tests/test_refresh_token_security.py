from app.core.security import create_refresh_token, hash_refresh_token


def test_create_refresh_token_not_empty():
    token = create_refresh_token()
    assert token
    assert isinstance(token, str)


def test_create_refresh_token_are_different():
    token1 = create_refresh_token()
    token2 = create_refresh_token()
    assert token1 != token2


def test_create_refresh_token_is_urlsafe_string():
    token = create_refresh_token()
    assert token
    assert all(c.isalnum() or c in "-_" for c in token)


def test_hash_refresh_token_deterministic():
    token = create_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_hash_refresh_token_different_for_different_tokens():
    token1 = create_refresh_token()
    token2 = create_refresh_token()
    assert hash_refresh_token(token1) != hash_refresh_token(token2)


def test_hash_refresh_token_not_equal_to_original():
    token = create_refresh_token()
    assert hash_refresh_token(token) != token


def test_hash_refresh_token_is_sha256_hexdigest():
    token = create_refresh_token()
    digest = hash_refresh_token(token)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)
