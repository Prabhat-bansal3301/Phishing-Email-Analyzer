
from unittest.mock import patch, Mock

from app.virustotal import get_file_report


TEST_HASH = "a" * 64


def test_missing_api_key():
    with patch("app.virustotal.os.getenv", return_value=None):
        try:
            get_file_report(TEST_HASH)
            assert False, "Expected RuntimeError"
        except RuntimeError:
            pass


def test_missing_hash():
    try:
        get_file_report("")
        assert False, "Expected ValueError"
    except ValueError:
        pass



def test_successful_report():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 60,
                    "harmless": 5,
                    "type-unsupported": 6
                }
            }
        }
    }

    with patch("app.virustotal.requests.get", return_value=mock_response):
        result = get_file_report(TEST_HASH)

    assert result["status"] == "success"
    assert result["stats"]["malicious"] == 2
    assert result["stats"]["suspicious"] == 1
    assert result["stats"]["undetected"] == 60
    assert result["stats"]["harmless"] == 5
    assert result["stats"]["unsupported"] == 6
    assert result["stats"]["total_engines"] == 74



def test_hash_not_found():
    mock_response = Mock()
    mock_response.status_code = 404

    with patch("app.virustotal.requests.get", return_value=mock_response):
        result = get_file_report(TEST_HASH)

    assert result["status"] == "not_found"


def test_rate_limited():
    mock_response = Mock()
    mock_response.status_code = 429

    with patch("app.virustotal.requests.get", return_value=mock_response):
        result = get_file_report(TEST_HASH)

    assert result["status"] == "rate_limited"


def test_unauthorized_response():
    mock_response = Mock()
    mock_response.status_code = 401

    with patch("app.virustotal.requests.get", return_value=mock_response):
        result = get_file_report(TEST_HASH)

    assert result["status"] == "unauthorized"


def test_forbidden_response():
    mock_response = Mock()
    mock_response.status_code = 403

    with patch("app.virustotal.requests.get", return_value=mock_response):
        result = get_file_report(TEST_HASH)

    assert result["status"] == "forbidden"


if __name__ == "__main__":
    test_missing_api_key()
    test_missing_hash()
    test_successful_report()
    test_hash_not_found()
    test_rate_limited()
    test_unauthorized_response()
    test_forbidden_response()

    print("All VirusTotal tests passed!")
