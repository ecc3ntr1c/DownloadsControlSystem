from dataclasses import dataclass, field


class ScannerError(Exception):
    def __init__(self, message, *, retryable=False, retry_after=None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


@dataclass(frozen=True)
class ScanOutcome:
    verdict: str
    signature: str = ""
    summary: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
