import unittest
from unittest.mock import patch, MagicMock
from src import updater


class TestUpdater(unittest.TestCase):

    @patch('src.updater.subprocess.run')
    def test_check_updates_no_updates(self, mock_run: MagicMock) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "0\n"
        mock_run.return_value = mock_result

        result = updater.check_updates(auto=False)
        self.assertFalse(result)

    @patch('src.updater.subprocess.run')
    def test_check_updates_has_updates(self, mock_run: MagicMock) -> None:
        def side_effect(cmd, **kwargs):
            mock = MagicMock()
            if "rev-list" in cmd:
                mock.stdout = "3\n"
            else:
                mock.stdout = ""
            return mock

        mock_run.side_effect = side_effect

        result = updater.check_updates(auto=False)
        self.assertTrue(result)
        self.assertTrue(updater.update_available)

    @patch('src.updater.subprocess.run')
    def test_check_updates_error(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = Exception("git not found")
        result = updater.check_updates(auto=False)
        self.assertFalse(result)

    @patch('src.updater.subprocess.run')
    def test_check_updates_auto_flag(self, mock_run: MagicMock) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "0\n"
        mock_run.return_value = mock_result

        result = updater.check_updates(auto=True)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
