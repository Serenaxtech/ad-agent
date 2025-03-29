import pytest
from forwarder import HTTPForwarder, ForwarderError
from unittest.mock import patch

def test_forward_request_success():
    with patch("requests.Session.request") as mock_request:
        mock_response = mock_request.return_value
        mock_response.status_code = 200
        mock_response.text = '{"message": "Success"}'

        forwarder = HTTPForwarder()
        response = forwarder.forward_request("GET", "http://localhost:3000")

        assert response.status_code == 200
        assert response.text == '{"message": "Success"}'

def test_forward_request_failure():
    with patch("requests.Session.request") as mock_request:
        mock_request.side_effect = Exception("Connection error")

        forwarder = HTTPForwarder()

        with pytest.raises(ForwarderError, match="Failed to forward request"):
            forwarder.forward_request("GET", "http://example.com")