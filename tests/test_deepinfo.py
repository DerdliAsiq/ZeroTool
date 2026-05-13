import unittest
from unittest.mock import patch, MagicMock
from src.deepinfo import (
    _gather_whois,
    _gather_subdomains,
    _gather_dns,
    _gather_ports,
    _gather_security_headers,
    _gather_robots_txt,
    _gather_social_media,
    _gather_reverse_dns,
    _gather_common_files,
    deep_info_gathering,
)


class TestDeepinfo(unittest.TestCase):

    @patch('src.deepinfo.socket.socket')
    def test_whois_with_emails(self, mock_socket: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.recv.side_effect = [
            b"contact@example.com\r\n",
            b"admin@example.com\r\n",
            b"",
        ]
        mock_socket.return_value = mock_instance

        result = _gather_whois("example.com")
        self.assertIsNone(result)

    @patch('src.deepinfo.requests.get')
    def test_subdomains_found(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com"},
        ]
        mock_get.return_value = mock_response

        result = _gather_subdomains("example.com")
        self.assertIsNone(result)

    @patch('src.deepinfo.requests.get')
    def test_dns_records(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "Answer": [{"data": "192.0.2.1"}]
        }
        mock_get.return_value = mock_response

        result = _gather_dns("example.com")
        self.assertIsNone(result)

    @patch('src.deepinfo.socket.socket')
    def test_ports_all_closed(self, mock_socket: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 1
        mock_socket.return_value = mock_instance

        result = _gather_ports("93.184.216.34")
        self.assertIsInstance(result, set)

    @patch('src.deepinfo.requests.get')
    def test_security_headers_found(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        }
        mock_get.return_value = mock_response

        result = _gather_security_headers("example.com")
        self.assertIsNone(result)

    @patch('src.deepinfo.requests.get')
    def test_robots_txt_found(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
        mock_get.return_value = mock_response

        result = _gather_robots_txt("example.com")
        self.assertIsNone(result)

    def test_social_media_found(self) -> None:
        html = """
        <a href="https://facebook.com/example">FB</a>
        <a href="https://twitter.com/example">Twitter</a>
        <a href="https://github.com/example">GitHub</a>
        """
        result = _gather_social_media(html)
        self.assertIsNone(result)

    def test_social_media_not_found(self) -> None:
        html = "<html><body>No links here</body></html>"
        result = _gather_social_media(html)
        self.assertIsNone(result)

    def test_social_media_no_html(self) -> None:
        result = _gather_social_media(None)
        self.assertIsNone(result)

    @patch('src.deepinfo.socket.gethostbyaddr')
    def test_reverse_dns_found(self, mock_gethost: MagicMock) -> None:
        mock_gethost.return_value = ("server.example.com", [], ["93.184.216.34"])
        result = _gather_reverse_dns("93.184.216.34")
        self.assertIsNone(result)

    @patch('src.deepinfo.requests.head')
    def test_common_files_found(self, mock_head: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_head.return_value = mock_response

        result = _gather_common_files("example.com")
        self.assertIsNone(result)

    @patch('src.deepinfo._gather_whois')
    @patch('src.deepinfo._gather_subdomains')
    @patch('src.deepinfo._gather_dns')
    @patch('src.deepinfo._gather_ports')
    @patch('src.deepinfo._gather_web_infra')
    @patch('src.deepinfo._get_homepage')
    @patch('src.deepinfo._gather_robots_txt')
    @patch('src.deepinfo._gather_sitemap')
    @patch('src.deepinfo._gather_security_headers')
    @patch('src.deepinfo._gather_tech')
    @patch('src.deepinfo._gather_social_media')
    @patch('src.deepinfo._gather_ssl')
    @patch('src.deepinfo._gather_reverse_dns')
    @patch('src.deepinfo._gather_geoip')
    @patch('src.deepinfo._gather_common_files')
    @patch('src.deepinfo._gather_emails')
    @patch('src.deepinfo._gather_wayback')
    def test_deep_info_gathering_full(
        self, *mocks: MagicMock
    ) -> None:
        result = deep_info_gathering("example.com", "93.184.216.34")
        self.assertIsNone(result)
        for m in mocks:
            m.assert_called_once()


if __name__ == '__main__':
    unittest.main()
