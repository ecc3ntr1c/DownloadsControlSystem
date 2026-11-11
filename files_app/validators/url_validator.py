import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

from files_app.services.policies import DownloadPolicyConfig

from ..downloaders.exceptions import (
    InvalidDownloadUrlError,
    ProtectedDownloadError,
)
from ..downloaders.protected_rules import (
    ProtectedDownloadRuleService,
)


@dataclass(frozen=True)
class ValidatedUrl:
    """
    HTTP/HTTPS URL, успешно прошедший проверки
    политики скачивания.
    """

    original: str
    parsed: ParseResult
    hostname: str
    port: int
    resolved_addresses: tuple[str, ...]
    has_credentials: bool


class DownloadUrlValidator:
    """
    Проверяет HTTP/HTTPS URL перед обращением к источнику.

    Проверяет:
    - корректность структуры URL;
    - поддерживаемую схему;
    - разрешение HTTP/HTTPS глобальной политикой;
    - username/password;
    - allowlist/blacklist доменов;
    - allowlist/blacklist портов;
    - ProtectedDownloadRule;
    - DNS;
    - IPv4/IPv6;
    - private/internal/special IP.
    """

    SUPPORTED_SCHEMES = frozenset(
        {
            "http",
            "https",
        }
    )

    DEFAULT_PORTS = {
        "http": 80,
        "https": 443,
    }

    def __init__(
        self,
        protected_rule_service: ProtectedDownloadRuleService,
    ) -> None:
        self.protected_rule_service = protected_rule_service

    def validate(
        self,
        *,
        url: str,
        policy: DownloadPolicyConfig,
    ) -> ValidatedUrl:
        """
        Проверить URL согласно активной DownloadPolicy.

        При успешной проверке возвращает ValidatedUrl.
        При нарушении политики выбрасывает исключение.
        """

        if not isinstance(url, str) or not url.strip():
            raise InvalidDownloadUrlError(
                "URL не указан"
            )
        if len(url) > 4096 or "\\" in url or any(ord(char) < 32 or ord(char) == 127 for char in url):
            raise InvalidDownloadUrlError("Некорректные символы или длина URL.")

        try:
            parsed = urlparse(url.strip())
        except ValueError as exc:
            raise InvalidDownloadUrlError(
                "Некорректный URL"
            ) from exc

        scheme = parsed.scheme.lower()

        # --------------------------------------------------
        # 1. Схема
        # --------------------------------------------------

        if not scheme:
            raise InvalidDownloadUrlError(
                "URL не содержит схему"
            )

        if scheme not in self.SUPPORTED_SCHEMES:
            raise InvalidDownloadUrlError(
                f"Схема {scheme!r} "
                "не поддерживается HTTP downloader"
            )

        # --------------------------------------------------
        # 2. Разрешение HTTP / HTTPS глобальной политикой
        # --------------------------------------------------

        if (
            scheme == "http"
            and not policy.allow_http
        ):
            raise InvalidDownloadUrlError(
                "HTTP-загрузка запрещена политикой"
            )

        if (
            scheme == "https"
            and not policy.allow_https
        ):
            raise InvalidDownloadUrlError(
                "HTTPS-загрузка запрещена политикой"
            )

        # --------------------------------------------------
        # 3. Hostname
        # --------------------------------------------------

        try:
            raw_hostname = parsed.hostname
        except ValueError as exc:
            raise InvalidDownloadUrlError(
                "Некорректный hostname в URL"
            ) from exc

        if not raw_hostname:
            raise InvalidDownloadUrlError(
                "URL не содержит hostname"
            )

        hostname = self._normalize_hostname(
            raw_hostname
        )

        # --------------------------------------------------
        # 4. Username / password
        # --------------------------------------------------

        has_credentials = parsed.username is not None or parsed.password is not None

        if (
            has_credentials
            and not policy.allow_url_credentials
        ):
            raise InvalidDownloadUrlError(
                "URL с username/password "
                "запрещён политикой"
            )

        # --------------------------------------------------
        # 5. Доменная политика
        # --------------------------------------------------

        self._validate_domain(
            hostname=hostname,
            policy=policy,
        )

        # --------------------------------------------------
        # 6. Эффективный порт
        # --------------------------------------------------

        try:
            explicit_port = parsed.port
        except ValueError as exc:
            raise InvalidDownloadUrlError(
                "Некорректный порт в URL"
            ) from exc

        if explicit_port is not None:
            port = explicit_port
        else:
            port = self.DEFAULT_PORTS[scheme]

        self._validate_port(
            port=port,
            policy=policy,
        )

        # --------------------------------------------------
        # 7. Защищённые правила суперадмина
        # --------------------------------------------------

        matched_rule = (
            self.protected_rule_service.check(
                parsed_url=parsed,
            )
        )

        if matched_rule is not None:
            raise ProtectedDownloadError(
                "URL запрещён защищённым правилом "
                f"«{matched_rule.name}»: "
                f"{matched_rule.reason}"
            )

        # --------------------------------------------------
        # 8. DNS / IP
        # --------------------------------------------------

        addresses = self._resolve_addresses(
            hostname=hostname,
            port=port,
        )

        self._validate_network(
            addresses=addresses,
            policy=policy,
        )

        # --------------------------------------------------
        # 9. URL успешно прошёл все проверки
        # --------------------------------------------------

        return ValidatedUrl(
            original=url.strip(),
            parsed=parsed,
            hostname=hostname,
            port=port,
            resolved_addresses=tuple(
                sorted(addresses)
            ),
            has_credentials=has_credentials,
        )

    @staticmethod
    def _normalize_hostname(
        hostname: str,
    ) -> str:
        """
        Привести hostname к единому виду.

        Например:
        EXAMPLE.COM. -> example.com

        Для IDN используется ASCII/IDNA представление.
        """

        hostname = hostname.strip().rstrip(".")

        if not hostname or "%" in hostname:
            raise InvalidDownloadUrlError(
                "Hostname пуст"
            )

        # Если hostname уже является IPv4/IPv6,
        # возвращаем его в каноническом виде.
        try:
            return str(
                ipaddress.ip_address(hostname)
            )
        except ValueError:
            pass

        try:
            normalized = (
                hostname
                .encode("idna")
                .decode("ascii")
                .lower()
            )
        except UnicodeError as exc:
            raise InvalidDownloadUrlError(
                "Некорректное доменное имя"
            ) from exc

        if not normalized:
            raise InvalidDownloadUrlError(
                "Hostname пуст"
            )

        return normalized

    @classmethod
    def _domain_matches(
        cls,
        hostname: str,
        configured_domain: str,
    ) -> bool:
        """
        Проверить соответствие hostname домену
        из allowlist/blacklist.

        example.com совпадает с:
        - example.com
        - www.example.com
        - cdn.download.example.com

        Но не совпадает с:
        - evil-example.com
        - example.com.evil.com
        """

        configured_domain = (
            configured_domain
            .strip()
            .lower()
            .lstrip(".")
            .rstrip(".")
        )

        if not configured_domain:
            return False

        try:
            configured_domain = (
                configured_domain
                .encode("idna")
                .decode("ascii")
                .lower()
            )
        except UnicodeError as exc:
            raise InvalidDownloadUrlError(
                "Некорректный домен "
                "в политике скачивания"
            ) from exc

        return (
            hostname == configured_domain
            or hostname.endswith(
                f".{configured_domain}"
            )
        )

    def _validate_domain(
        self,
        *,
        hostname: str,
        policy: DownloadPolicyConfig,
    ) -> None:
        """
        Проверить allowlist/blacklist доменов.

        Blacklist имеет приоритет над allowlist.
        Пустой allowed_domains означает:
        разрешены любые домены, не попавшие в blacklist.
        """

        for blocked_domain in policy.blocked_domains:
            if self._domain_matches(
                hostname,
                str(blocked_domain),
            ):
                raise InvalidDownloadUrlError(
                    "Домен запрещён политикой"
                )

        if not policy.allowed_domains:
            return

        allowed = any(
            self._domain_matches(
                hostname,
                str(allowed_domain),
            )
            for allowed_domain
            in policy.allowed_domains
        )

        if not allowed:
            raise InvalidDownloadUrlError(
                "Домен отсутствует в allowlist"
            )

    @staticmethod
    def _validate_port(
        *,
        port: int,
        policy: DownloadPolicyConfig,
    ) -> None:
        """
        Проверить порт согласно политике.

        blocked_ports имеет приоритет.
        Пустой allowed_ports означает:
        разрешены любые порты, кроме blocked_ports.
        """

        if not 1 <= port <= 65535:
            raise InvalidDownloadUrlError(
                "Порт находится вне диапазона "
                "1-65535"
            )

        try:
            blocked_ports = {
                int(value)
                for value in policy.blocked_ports
            }

            allowed_ports = {
                int(value)
                for value in policy.allowed_ports
            }
        except (TypeError, ValueError) as exc:
            raise InvalidDownloadUrlError(
                "В политике скачивания указан "
                "некорректный порт"
            ) from exc

        if port in blocked_ports:
            raise InvalidDownloadUrlError(
                "Порт запрещён политикой"
            )

        if (
            allowed_ports
            and port not in allowed_ports
        ):
            raise InvalidDownloadUrlError(
                "Порт отсутствует в allowlist"
            )

    @staticmethod
    def _resolve_addresses(
        *,
        hostname: str,
        port: int,
    ) -> set[str]:
        """
        Получить все IPv4/IPv6 адреса источника.

        Если hostname сам является IP,
        DNS-запрос не выполняется.
        """

        try:
            address = ipaddress.ip_address(
                hostname
            )
        except ValueError:
            address = None

        if address is not None:
            return {
                str(address)
            }

        try:
            results = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise InvalidDownloadUrlError(
                "Не удалось разрешить hostname "
                "через DNS"
            ) from exc

        addresses: set[str] = set()

        for result in results:
            raw_address = result[4][0]

            try:
                address = ipaddress.ip_address(
                    raw_address
                )
            except ValueError:
                continue

            addresses.add(
                str(address)
            )

        if not addresses:
            raise InvalidDownloadUrlError(
                "Hostname не имеет доступных "
                "IPv4/IPv6 адресов"
            )

        return addresses

    @staticmethod
    def _validate_network(
        *,
        addresses: set[str],
        policy: DownloadPolicyConfig,
    ) -> None:
        """
        Проверить сетевые адреса.

        Невалидные для обычного HTTP назначения
        адреса запрещаются всегда.

        Private/internal адреса разрешаются только
        при allow_private_networks=True.
        """

        for raw_address in addresses:
            address = ipaddress.ip_address(
                raw_address
            )
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped

            # Эти типы адресов не являются нормальной
            # точкой назначения для загрузки файла.
            if address.is_unspecified or address.is_loopback or address.is_link_local:
                raise InvalidDownloadUrlError(
                    "Источник указывает "
                    "на локальный или служебный IP-адрес"
                )

            if address.is_multicast:
                raise InvalidDownloadUrlError(
                    "Источник указывает "
                    "на multicast IP-адрес"
                )

            if policy.allow_private_networks and policy.allowed_domains and not address.is_reserved:
                continue

            # Если private/internal сети запрещены,
            # разрешаем только глобально маршрутизируемые
            # адреса.
            if not address.is_global:
                raise InvalidDownloadUrlError(
                    "Источник указывает "
                    "на внутренний или специальный "
                    "IP-адрес"
                )
