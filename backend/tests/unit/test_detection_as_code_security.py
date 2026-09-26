"""Detection-as-Code content security tests (V2.17).

The scanner must reject *real credential values* while never rejecting
legitimate detection markers (e.g. the shipped ``credential_exposure.yar``
literal ``client_secret=`` with no attached value).
"""

from app.services.detection_as_code.security import scan_secret_leakage


class TestRecognizedCredentialFormats:
    def test_aws_access_key(self):
        findings = scan_secret_leakage("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
        assert any("aws_access_key" in f for f in findings)

    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert any("jwt" in f for f in scan_secret_leakage(token))

    def test_github_token(self):
        token = "ghp_" + "ABCdef123" * 4
        assert len(token) == 40
        assert any("github_token" in f for f in scan_secret_leakage(f"token = {token}"))

    def test_slack_token(self):
        token = "xox" + "b-123456789012-abcdefghijklmnopqrst"

        assert any(
            "slack_token" in f
            for f in scan_secret_leakage(f"slack_token {token}")
        )

    def test_pem_private_key_only_complete_block(self):
        begin_only = "index of -----BEGIN PRIVATE KEY----- in decoded content"
        end_only = "trailing -----END PRIVATE KEY----- marker"
        full = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n"
            "-----END RSA PRIVATE KEY-----"
        )
        assert scan_secret_leakage(begin_only) == []
        assert scan_secret_leakage(end_only) == []
        assert any("pem_private_key" in f for f in scan_secret_leakage(full))


class TestKeyValueAssignments:
    def test_plain_text_password_rejected(self):
        findings = scan_secret_leakage("password = Sup3rSecret2024!")
        assert any("credential-key assignment" in f for f in findings)

    def test_bare_marker_not_a_leak(self):
        assert scan_secret_leakage("client_secret=") == []
        assert scan_secret_leakage("search for aws_secret_access_key= ") == []

    def test_dictionary_word_not_a_leak(self):
        assert scan_secret_leakage("token = authentication") == []

    def test_short_value_not_a_leak(self):
        assert scan_secret_leakage("password = abc") == []

    def test_explicit_placeholder_not_a_leak(self):
        assert scan_secret_leakage("password = CHANGE_ME") == []
        assert scan_secret_leakage("api_key = 1234example5678") == []
        assert scan_secret_leakage("token = <redacted>") == []

    def test_url_value_not_a_leak(self):
        assert scan_secret_leakage("token = https://example.com/token") == []


class TestDeterminism:
    def test_ordering_is_deterministic(self):
        text = (
            "api_key = Aa1234567890xyz\n"
            "-----BEGIN PRIVATE KEY-----\nMIIEow\n-----END PRIVATE KEY-----\n"
            "AKIAIOSFODNN7EXAMPLE\n"
        )
        assert scan_secret_leakage(text) == scan_secret_leakage(text)

    def test_clean_content_is_clean(self):
        assert scan_secret_leakage("rule: hello\ncondition: selection") == []


class TestShippedRuleTolerance:
    def test_credential_exposure_markers_pass(self):
        text = (
            "condition: any of them\n"
            "client_secret=\n"
            "aws_secret_access_key=\n"
            "api_key=\n"
        )
        assert scan_secret_leakage(text) == []