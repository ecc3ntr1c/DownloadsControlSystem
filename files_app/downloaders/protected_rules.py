import ipaddress
from dataclasses import dataclass

from files_app.models import ProtectedDownloadRule


@dataclass(frozen=True)
class MatchedProtectedRule:
    """
    Зафиксированное совпавшее защищённое правило.
    """

    rule_id: int
    name: str
    reason: str


class ProtectedDownloadRuleService:
    """
    Проверяет URL по активным ProtectedDownloadRule.

    Эти правила являются дополнительным уровнем
    защиты поверх обычной DownloadPolicy.
    """

    @staticmethod
    def get_active_rules() -> list[ProtectedDownloadRule]:
        return list(
            ProtectedDownloadRule.objects.filter(
                is_active=True,
            ).order_by("id")
        )

    def check(
        self,
        *,
        parsed_url,
    ) -> MatchedProtectedRule | None:

        hostname = self._normalize_host(parsed_url.hostname or "")

        scheme = parsed_url.scheme.lower()

        has_credentials = parsed_url.username is not None or parsed_url.password is not None

        for rule in self.get_active_rules():

            if not self._scheme_matches(
                rule=rule,
                scheme=scheme,
            ):
                continue

            if not self._host_matches(
                rule=rule,
                hostname=hostname,
            ):
                continue

            if not self._credentials_match(
                rule=rule,
                has_credentials=has_credentials,
            ):
                continue

            return MatchedProtectedRule(
                rule_id=rule.id,
                name=rule.name,
                reason=rule.reason,
            )

        return None

    @staticmethod
    def _scheme_matches(
        *,
        rule: ProtectedDownloadRule,
        scheme: str,
    ) -> bool:

        if not rule.scheme:
            return True

        return (
            rule.scheme.lower() == scheme
        )

    @classmethod
    def _host_matches(
        cls,
        *,
        rule: ProtectedDownloadRule,
        hostname: str,
    ) -> bool:

        if not rule.host_pattern.strip():
            return True
        pattern = cls._normalize_host(rule.host_pattern.strip().lstrip("."))
        return bool(pattern) and (hostname == pattern or hostname.endswith(f".{pattern}"))

    @staticmethod
    def _normalize_host(host):
        host = host.rstrip(".").lower()
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return host.encode("idna").decode("ascii")

    @staticmethod
    def _credentials_match(
        *,
        rule: ProtectedDownloadRule,
        has_credentials: bool,
    ) -> bool:

        if (
            rule.credentials_mode
            == ProtectedDownloadRule.CredentialsMode.ANY
        ):
            return True

        if (
            rule.credentials_mode
            == ProtectedDownloadRule.CredentialsMode.REQUIRED
        ):
            return has_credentials

        if (
            rule.credentials_mode
            == ProtectedDownloadRule.CredentialsMode.FORBIDDEN
        ):
            return not has_credentials

        return False
