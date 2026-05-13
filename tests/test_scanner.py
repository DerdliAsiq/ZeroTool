import unittest
from unittest.mock import patch, MagicMock
from src.scanner import scan_and_fingerprint


class TestScanner(unittest.TestCase):

    @patch('src.scanner.socket.socket')
    def test_scan_no_open_ports(self, mock_socket: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.connect_ex.return_value = 1
        mock_socket.return_value = mock_instance

        result = scan_and_fingerprint("example.com", "93.184.216.34")
        self.assertIsNone(result)

    @patch('src.scanner.socket.socket')
    def test_scan_with_open_ports(self, mock_socket: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.connect_ex.side_effect = [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        mock_instance.recv.return_value = b"SSH-2.0-OpenSSH\r\n"
        mock_socket.return_value = mock_instance

        result = scan_and_fingerprint("example.com", "93.184.216.34")
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
