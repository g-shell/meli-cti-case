import pytest

from pydantic import ValidationError

from app.models import TriageRequest


@pytest.mark.parametrize(
    "value",
    [
        "a" * 32,
        "b" * 40,
        "c" * 64,
        "ABCDEF" * 10 + "ABCD",
    ],
)
def test_accepts_supported_hex_hashes(value):
    request = TriageRequest(hash=value)

    assert request.hash == value.lower()


@pytest.mark.parametrize(
    "value",
    [
        "suposto_hash",
        "z" * 64,
        "a" * 31,
        "",
        "a" * 65,
    ],
)
def test_rejects_invalid_hashes(value):
    with pytest.raises(ValidationError):
        TriageRequest(hash=value)


def test_requires_at_least_one_provider():
    with pytest.raises(ValidationError):
        TriageRequest(
            hash="a" * 64,
            providers=[],
        )