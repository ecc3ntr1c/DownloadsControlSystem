import re

from django.db.models import Q

from files_app.models import FileTypePolicy, ProhibitedSoftwareMatch, ProhibitedSoftwareRule
from requests_app.source_urls import display_source_url


class RuleConfigurationError(ValueError):
    pass


def file_type_blockers(stored_file):
    extension = stored_file.extension.lower().lstrip(".")
    mime = stored_file.mime_type.lower()
    extensions = Q(extension__iexact=extension) | Q(extension__iexact=f".{extension}")
    applicable = FileTypePolicy.objects.filter(
        (extensions & (Q(mime_type="") | Q(mime_type__iexact=mime)))
        | (Q(extension="") & Q(mime_type__iexact=mime) & ~Q(mime_type=""))
    )
    reasons = set()
    for policy in applicable:
        if not policy.is_allowed:
            reasons.add("Тип файла запрещён политикой.")
        if stored_file.size_bytes > policy.max_size_mb * 1024 * 1024:
            reasons.add("Размер превышает лимит для этого типа файла.")
        if policy.requires_unpacking:
            reasons.add("Политика требует отдельной распаковки и проверки.")
        if policy.requires_sandbox:
            reasons.add("Политика требует отдельной проверки в песочнице.")
    return sorted(reasons)


def find_prohibited_matches(software_request, hostname):
    fields = {
        ProhibitedSoftwareRule.TargetField.URL: software_request.source_url,
        ProhibitedSoftwareRule.TargetField.DESCRIPTION: software_request.description,
        ProhibitedSoftwareRule.TargetField.BUSINESS_REASON: software_request.business_reason,
        ProhibitedSoftwareRule.TargetField.DOMAIN: hostname,
    }
    matches = []
    for rule in ProhibitedSoftwareRule.objects.filter(is_active=True).order_by("pk"):
        if not rule.pattern.strip():
            raise RuleConfigurationError("В реестре запрещённого ПО есть правило с пустым шаблоном.")
        for field, value in _targets(rule, fields):
            if _matches(rule, value):
                if field == ProhibitedSoftwareRule.TargetField.URL:
                    value = display_source_url(value)
                matches.append(ProhibitedSoftwareMatch(
                    request=software_request, rule=rule, matched_field=field, matched_value=value[:2048],
                ))
                break
    return matches


def _targets(rule, fields):
    if rule.match_type == ProhibitedSoftwareRule.MatchType.DOMAIN:
        field = ProhibitedSoftwareRule.TargetField.DOMAIN
    elif rule.match_type == ProhibitedSoftwareRule.MatchType.URL_CONTAINS:
        field = ProhibitedSoftwareRule.TargetField.URL
    else:
        field = rule.target_field
    if field == ProhibitedSoftwareRule.TargetField.ANY:
        return fields.items()
    if field not in fields:
        raise RuleConfigurationError("В реестре запрещённого ПО указано неизвестное поле.")
    return [(field, fields[field])]


def _matches(rule, value):
    kind = ProhibitedSoftwareRule.MatchType
    pattern = rule.pattern.strip()
    if rule.match_type == kind.REGEX:
        try:
            return bool(re.search(pattern, value, flags=re.IGNORECASE))
        except re.error as exc:
            raise RuleConfigurationError("В реестре запрещённого ПО есть некорректное выражение.") from exc
    if rule.match_type == kind.DOMAIN:
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
            pattern = pattern.strip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise RuleConfigurationError("В реестре запрещённого ПО указан некорректный домен.") from exc
        return bool(pattern) and (value == pattern or value.endswith(f".{pattern}"))
    if rule.match_type == kind.EXACT:
        return value.casefold() == pattern.casefold()
    if rule.match_type in (kind.CONTAINS, kind.URL_CONTAINS):
        return pattern.casefold() in value.casefold()
    raise RuleConfigurationError("В реестре запрещённого ПО указан неизвестный вид правила.")


def prevents_release(rule):
    return not rule.allow_security_override or not rule.requires_security_confirmation
