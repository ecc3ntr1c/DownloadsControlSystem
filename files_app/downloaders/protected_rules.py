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

        hostname = (
            parsed_url.hostname or ""
        ).lower().rstrip(".")

        scheme = parsed_url.scheme.lower()

        has_credentials = bool(
            parsed_url.username
            or parsed_url.password
        )

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

    @staticmethod
    def _host_matches(
        *,
        rule: ProtectedDownloadRule,
        hostname: str,
    ) -> bool:

        pattern = (
            rule.host_pattern
            .lower()
            .rstrip(".")
        )

        if not pattern:
            return False

        # Точное совпадение.
        if hostname == pattern:
            return True

        # Совпадение с поддоменами.
        return hostname.endswith(
            f".{pattern}"
        )

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