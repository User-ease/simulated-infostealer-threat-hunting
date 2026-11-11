import unittest

from scripts.analyze_week9_windows import archive_mode


class WindowsTarModeTests(unittest.TestCase):
    def test_traditional_operations(self):
        for flags, expected in (("cf", "create"), ("cvf", "create"), ("fc", "create"),
                                ("tf", "list"), ("xf", "extract")):
            with self.subTest(flags=flags):
                self.assertEqual(archive_mode(f'tar.exe {flags} "profile copy.tar"'), expected)

    def test_operand_is_never_a_mode(self):
        for command in ("tar.exe -- cf", "tar.exe --file cf profile", "tar.exe docs cf out.tar"):
            with self.subTest(command=command):
                self.assertEqual(archive_mode(command), "unknown")
        self.assertEqual(archive_mode("tar.exe tf cf"), "list")

    def test_missing_archive_and_mixed_modes(self):
        for command in ("tar.exe cf", "tar.exe ctf out.tar", "tar.exe cf out.tar --list"):
            with self.subTest(command=command):
                self.assertEqual(archive_mode(command), "unknown")
