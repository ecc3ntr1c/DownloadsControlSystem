import hashlib
import struct
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from scanning.clamav import ClamAVScanner, ScannerError
from scanning.models import ScanResult


class ClamAVTests(SimpleTestCase):
    def scan_with_reply(self, reply, *, altered=False):
        content = b"Local antivirus protocol test fixture"
        stored_file = SimpleNamespace(
            size_bytes=len(content),
            file_hash_sha256=hashlib.sha256(content if not altered else b"different").hexdigest(),
        )
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = reply
        with (
            patch("scanning.clamav.FileStorageService.open_file", return_value=BytesIO(content)),
            patch.object(ClamAVScanner, "_connect", return_value=connection),
        ):
            return ClamAVScanner().scan(stored_file), connection

    def test_sends_file_contents_with_clamd_stream_framing(self):
        outcome, connection = self.scan_with_reply([b"stream:", b" OK\0"])
        self.assertEqual(outcome.verdict, ScanResult.Verdict.CLEAN)
        self.assertEqual(connection.sendall.call_args_list[0].args, (b"zINSTREAM\0",))
        payload = connection.sendall.call_args_list[1].args[0]
        self.assertEqual(struct.unpack("!I", payload[:4])[0], len(payload[4:]))
        self.assertEqual(payload[4:], b"Local antivirus protocol test fixture")
        self.assertEqual(connection.sendall.call_args_list[2].args, (b"\0" * 4,))

    def test_classifies_positive_detection_and_scan_limit(self):
        for signature, expected in [
            ("LocalFixture.Detection", ScanResult.Verdict.MALICIOUS),
            ("Heuristics.Limits.Exceeded", ScanResult.Verdict.SUSPICIOUS),
        ]:
            with self.subTest(signature=signature):
                outcome, _ = self.scan_with_reply([f"stream: {signature} FOUND\0".encode()])
                self.assertEqual(outcome.verdict, expected)
                self.assertEqual(outcome.signature, signature)

    def test_aborted_or_invalid_reply_never_returns_clean(self):
        for reply in [[b"stream: OK", b""], [b"stream: Engine error ERROR\0"], [b"OK\0"]]:
            with self.subTest(reply=reply), self.assertRaises(ScannerError):
                self.scan_with_reply(reply)

    def test_detects_file_bytes_changed_since_download(self):
        with self.assertRaisesMessage(ScannerError, "Содержимое файла изменилось"):
            self.scan_with_reply([b"stream: OK\0"], altered=True)
