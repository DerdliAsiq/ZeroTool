import unittest
from unittest.mock import patch, MagicMock
from src.dirbuster import find_admin_panels


class TestDirbuster(unittest.TestCase):

    @patch('src.dirbuster.requests.head')
    def test_find_admin_panels_suffix_found(self, mock_head: MagicMock) -> None:
        def side_effect(url: str, **kwargs) -> MagicMock:
            mock = MagicMock()
            if "admin" in url and "login" not in url and url.count('.') >= 2:
                mock.status_code = 200
            else:
                mock.status_code = 404
            mock.headers = {}
            return mock

        mock_head.side_effect = side_effect
        result = find_admin_panels("example.com")
        self.assertIsNone(result)

    @patch('src.dirbuster.requests.head')
    def test_find_admin_panels_subdomain_found(self, mock_head: MagicMock) -> None:
        def side_effect(url: str, **kwargs) -> MagicMock:
            mock = MagicMock()
            if "http://admin.example.com/" == url or "https://admin.example.com/" == url:
                mock.status_code = 200
            else:
                mock.status_code = 404
            mock.headers = {}
            return mock

        mock_head.side_effect = side_effect
        result = find_admin_panels("example.com")
        self.assertIsNone(result)

    @patch('src.dirbuster.requests.head')
    def test_find_admin_panels_not_found(self, mock_head: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_head.return_value = mock_response
        result = find_admin_panels("example.com")
        self.assertIsNone(result)

    @patch('src.dirbuster.requests.head')
    def test_find_admin_panels_redirect_home(self, mock_head: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "/"}
        mock_head.return_value = mock_response
        result = find_admin_panels("example.com")
        self.assertIsNone(result)

    @patch('src.dirbuster.requests.head')
    def test_find_admin_panels_connection_error(self, mock_head: MagicMock) -> None:
        from requests.exceptions import ConnectionError
        mock_head.side_effect = ConnectionError()
        result = find_admin_panels("example.com")
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
