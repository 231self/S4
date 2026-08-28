from unittest.mock import Mock, patch

from s4_client.highlevel import S4Client


def test_attach_public_key_sends_target_api_key_credentials():
    response = Mock()
    response.raise_for_status.return_value = None
    with patch("s4_client.highlevel.requests.put", return_value=response) as put:
        S4Client("https://gateway.example/", "test-access", "test-secret", timeout=7).attach_public_key(
            "test-public-key"
        )

    put.assert_called_once_with(
        "https://gateway.example/dashboard/api/keys/public-key",
        headers={
            "x-s4-access-key": "test-access",
            "x-s4-secret-key": "test-secret",
        },
        json={"key_id": "test-access", "public_key_pem": "test-public-key"},
        timeout=7,
    )
