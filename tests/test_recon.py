import unittest
from unittest.mock import patch, MagicMock
from src.recon import get_subdomains, get_dns_records


class TestRecon(unittest.TestCase):

    @patch('src.recon.requests.get')
    def test_get_subdomains_found(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com"},
        ]
        mock_response.text = ""
        mock_get.return_value = mock_response

        result = get_subdomains("example.com")
        self.assertIsNone(result)

    @patch('src.recon.requests.get')
    def test_get_subdomains_empty(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.text = ""
        mock_get.return_value = mock_response

        result = get_subdomains("example.com")
        self.assertIsNone(result)

    @patch('src.recon.requests.get')
    def test_get_dns_records(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "Answer": [
                {"data": "192.0.2.1"},
                {"data": "192.0.2.2"},
            ]
        }
        mock_get.return_value = mock_response

        result = get_dns_records("example.com")
        self.assertIsNone(result)

    @patch('src.recon.requests.get')
    def test_get_dns_records_no_answer(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response

        result = get_dns_records("example.com")
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
