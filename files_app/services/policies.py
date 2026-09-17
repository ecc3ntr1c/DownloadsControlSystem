from dataclasses import dataclass, field

from files_app.models import DownloadsPolicy


@dataclass(frozen=True)
class DownloadPolicyConfig:
    """
    Конфигурация политики скачивания.

    Это уже не Django-модель,
    а обычный Python объект,
    который получает downloader.
    """

    allow_http: bool
    allow_https: bool

    allow_file_scheme: bool
    allow_url_credentials: bool

    reject_auth_required: bool
    reject_html_pages: bool

    allow_private_networks: bool

    max_file_size_bytes: int
    max_redirects: int

    allowed_domains: list[str] = field(
        default_factory=list
    )

    blocked_domains: list[str] = field(
        default_factory=list
    )

    allowed_ports: list[int] = field(
        default_factory=list
    )

    blocked_ports: list[int] = field(
        default_factory=list
    )

    allowed_file_hosts: list[str] = field(
        default_factory=list
    )

    blocked_file_hosts: list[str] = field(
        default_factory=list
    )

    allowed_file_base_paths: list[str] = field(
        default_factory=list
    )


class DownloadPolicyService:
    """
    Работа с политиками скачивания.
    """

    @staticmethod
    def get_active_policy() -> DownloadPolicyConfig:
        policy = (
            DownloadsPolicy.objects
            .filter(is_active=True)
            .first()
        )

        if not policy:
            raise RuntimeError(
                "Не найдена активная политика скачивания"
            )

        return DownloadPolicyConfig(
            allow_http=policy.allow_http,
            allow_https=policy.allow_https,

            allow_file_scheme=policy.allow_file_scheme,
            allow_url_credentials=(
                policy.allow_url_credentials
            ),

            reject_auth_required=(
                policy.reject_auth_required
            ),

            reject_html_pages=(
                policy.reject_html_pages
            ),

            allow_private_networks=(
                policy.allow_private_networks
            ),

            max_file_size_bytes=(
                policy.max_file_size_mb *
                1024 *
                1024
            ),

            max_redirects=(
                policy.max_redirects
            ),

            allowed_domains=(
                policy.allowed_domains
            ),

            blocked_domains=(
                policy.blocked_domains
            ),

            allowed_ports=(
                policy.allowed_ports
            ),

            blocked_ports=(
                policy.blocked_ports
            ),

            allowed_file_hosts=(
                policy.allowed_file_hosts
            ),

            blocked_file_hosts=(
                policy.blocked_file_hosts
            ),

            allowed_file_base_paths=(
                policy.allowed_file_base_paths
            ),
        )