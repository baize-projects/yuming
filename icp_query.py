import argparse
import hashlib
import itertools
import json
import os
import re
import secrets
import string
import sys
import time
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


SUPPORTED_TLDS = (".xyz", ".icu", ".top")
DEFAULT_DOMAINS = ("example.xyz", "test.icu", "demo.top")
DEFAULT_OUTPUT = f"expired_icp_results_{datetime.now().strftime('%Y%m%d')}.json"
DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 1.5
DEFAULT_RETRIES = 2
DEFAULT_STATE_FILE = "scan_state.json"
DEFAULT_MATCHES_FILE = "scan_matches.json"
DEFAULT_APICN_STATE_FILE = "apicn_scan_state.json"
DEFAULT_APICN_MATCHES_FILE = "apicn_scan_matches.json"
JYBLOG_URL = "https://who.jyblog.com/"
JYBLOG_WHOIS_API = "https://who.jyblog.com/api/whois/"
JYBLOG_BEIAN_API = "https://who.jyblog.com/api/beian/"
JYBLOG_SECRET_KEY = "jyblog20240103"
GENERATED_ALPHABET = string.ascii_lowercase + string.digits
TARGET_ALL = "all"
TARGET_UNREGISTERED_WITH_ICP = "unregistered-with-icp"

APIHZ_DISCOVERY_URL = "https://api.apihz.cn/getapi.php"
APIHZ_LAST_KNOWN_BASE_URL = "http://101.34.207.105/"
APIHZ_ICP_PATH = "api/wangzhan/icp.php"
APIHZ_PUBLIC_ID = "88888888"
APIHZ_PUBLIC_KEY = "88888888"

UOMG_URL = "https://api.uomg.com/api/icp"

APICN_DAY_PATH = "day/"
APICN_MAX_PAGE_SIZE = 1000
APICN_DEFAULT_START_DATE = "2024-01-01"

TRANSIENT_ERROR_WORDS = ("重试", "频次", "限流", "错误", "超时")
NO_RECORD_WORDS = ("没有备案", "无备案", "未备案", "未查询到备案")


@dataclass
class QueryResult:
    domain: str
    status: str
    provider: str
    raw: Any = None
    registered: bool | None = None
    expired: bool | None = None
    expiration_date: str | None = None
    creation_date: str | None = None
    updated_date: str | None = None
    registrar: str | None = None
    whois_server: str | None = None
    domain_statuses: list[str] | None = None
    name_servers: list[str] | None = None
    icp: str | None = None
    main_licence: str | None = None
    unit: str | None = None
    site_type: str | None = None
    approved_at: str | None = None
    error: str | None = None


class ProviderError(RuntimeError):
    pass


def normalize_domain(value: str) -> str | None:
    """Normalize a URL or domain-like string into a plain hostname."""
    value = value.strip()
    if not value or value.startswith("#"):
        return None

    if "://" not in value:
        value = f"//{value}"

    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        return None

    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def load_domains(path: str | None, cli_domains: list[str]) -> list[str]:
    values: list[str] = []

    if path:
        with open(path, "r", encoding="utf-8") as file:
            values.extend(file.readlines())

    values.extend(cli_domains)
    if not values:
        values.extend(DEFAULT_DOMAINS)

    domains: list[str] = []
    seen: set[str] = set()
    for value in values:
        domain = normalize_domain(value)
        if domain and domain not in seen:
            domains.append(domain)
            seen.add(domain)
    return domains


def filter_domains(domains: list[str], tlds: tuple[str, ...]) -> list[str]:
    return [domain for domain in domains if domain.endswith(tlds)]


def domain_label(domain: str) -> str:
    return domain.strip().lower().split(".", 1)[0]


def iter_generated_domains(
    tlds: tuple[str, ...],
    min_length: int,
    max_length: int,
    alphabet: str = GENERATED_ALPHABET,
    start_after: str | None = None,
) -> Any:
    if min_length < 1:
        raise ValueError("min_length 必须大于 0")
    if max_length < min_length:
        raise ValueError("max_length 不能小于 min_length")
    if not alphabet:
        raise ValueError("字符集不能为空")
    if not tlds:
        raise ValueError("后缀列表不能为空")

    normalized_tlds = tuple(
        tld if tld.startswith(".") else f".{tld}"
        for tld in tlds
    )
    normalized_start_after = normalize_domain(start_after) if start_after and "." in start_after else None
    start_after_label = start_after.strip().lower() if start_after and not normalized_start_after else None
    passed_start = normalized_start_after is None and start_after_label is None
    for length in range(min_length, max_length + 1):
        for chars in itertools.product(alphabet, repeat=length):
            label = "".join(chars)
            if not passed_start and start_after_label:
                if label == start_after_label:
                    passed_start = True
                continue
            for tld in normalized_tlds:
                domain = f"{label}{tld}"
                if not passed_start:
                    if normalized_start_after and domain == normalized_start_after:
                        passed_start = True
                    continue
                yield domain


def normalize_generated_alphabet(value: str) -> str:
    alphabet = value.strip().lower()
    if not alphabet:
        raise ValueError("字符集不能为空")
    if re.search(r"[^a-z0-9]", alphabet):
        raise ValueError("字符集只能包含小写字母和数字")

    deduped = "".join(dict.fromkeys(alphabet))
    if not deduped:
        raise ValueError("字符集不能为空")
    return deduped


def generated_domain_count(
    tlds: tuple[str, ...],
    min_length: int,
    max_length: int,
    alphabet: str = GENERATED_ALPHABET,
) -> int:
    label_count = sum(len(alphabet) ** length for length in range(min_length, max_length + 1))
    return label_count * len(tlds)


def build_generated_domains(
    tlds: tuple[str, ...],
    min_length: int,
    max_length: int,
    limit: int | None,
    start_after: str | None,
    alphabet: str = GENERATED_ALPHABET,
) -> list[str]:
    iterator = iter_generated_domains(
        tlds=tlds,
        min_length=min_length,
        max_length=max_length,
        alphabet=alphabet,
        start_after=start_after,
    )
    if limit is None:
        return list(iterator)
    if limit < 1:
        raise ValueError("limit 必须大于 0")
    return list(itertools.islice(iterator, limit))


def parse_date_arg(value: str | None, name: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError(f"{name} 必须是 YYYY-MM-DD 格式") from exc


def build_apicn_day_url(base_url: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", APICN_DAY_PATH)


def normalize_page_size(value: int) -> int:
    if value < 1:
        raise ValueError("apicn-page-size 必须大于 0")
    return min(value, APICN_MAX_PAGE_SIZE)


def find_first_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not isinstance(value, dict):
        return []

    preferred_keys = (
        "data",
        "list",
        "rows",
        "items",
        "records",
        "result",
        "results",
    )
    for key in preferred_keys:
        nested = value.get(key)
        found = find_first_list(nested)
        if found:
            return found

    for nested in value.values():
        found = find_first_list(nested)
        if found:
            return found
    return []


def extract_record_value(record: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(record, dict):
        return None
    lower_to_key = {str(key).lower(): key for key in record}
    for key in keys:
        actual_key = lower_to_key.get(key.lower())
        if actual_key is not None:
            value = record.get(actual_key)
            if value not in (None, ""):
                return value
    return None


def extract_record_domain(record: Any) -> str | None:
    if isinstance(record, str):
        return normalize_domain(record)
    if not isinstance(record, dict):
        return None

    domain_value = extract_record_value(
        record,
        (
            "domain",
            "domain_name",
            "domainName",
            "site_domain",
            "siteDomain",
            "web_domain",
            "webDomain",
            "url",
            "website",
            "homeUrl",
            "homepage",
        ),
    )
    if domain_value:
        return normalize_domain(str(domain_value))

    text = json.dumps(record, ensure_ascii=False)
    match = re.search(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}\b", text, re.I)
    return normalize_domain(match.group(0)) if match else None


def parse_apicn_day_records(
    raw: Any,
    query_date: str,
    page: int,
) -> tuple[list[QueryResult], int]:
    records = find_first_list(raw)
    parsed: list[QueryResult] = []
    seen: set[str] = set()

    for offset, record in enumerate(records):
        domain = extract_record_domain(record)
        if not domain or domain in seen:
            continue
        seen.add(domain)

        icp = extract_record_value(
            record,
            (
                "license",
                "serviceLicence",
                "service_license",
                "icp",
                "icpNo",
                "icp_no",
            ),
        )
        main_licence = extract_record_value(
            record,
            ("mainLicence", "main_license", "mainLicense", "main_licence"),
        )
        unit = extract_record_value(
            record,
            ("company", "unit", "unitName", "unit_name", "name"),
        )
        site_type = extract_record_value(
            record,
            ("type", "natureName", "nature_name", "unitType", "unit_type"),
        )
        approved_at = extract_record_value(
            record,
            ("audit_date", "auditDate", "approved_at", "time", "updateRecordTime"),
        )

        parsed.append(
            QueryResult(
                domain=domain,
                status="found",
                provider="apicn-day",
                raw={
                    "source_date": query_date,
                    "source_page": page,
                    "source_offset": offset,
                    "record": record,
                },
                icp=str(icp) if icp is not None else None,
                main_licence=str(main_licence) if main_licence is not None else None,
                unit=str(unit) if unit is not None else None,
                site_type=str(site_type) if site_type is not None else None,
                approved_at=str(approved_at) if approved_at is not None else None,
            )
        )

    return parsed, len(records)


def query_apicn_day_page(
    session: requests.Session,
    base_url: str,
    token: str,
    query_date: str,
    page: int,
    page_size: int,
    timeout: int,
) -> tuple[list[QueryResult], int, Any]:
    params = {
        "token": token,
        "date": query_date,
        "page": page,
        "limit": page_size,
    }
    raw = request_json(
        session=session,
        url=build_apicn_day_url(base_url),
        params=params,
        timeout=timeout,
        headers={"token": token, "Authorization": f"Bearer {token}"},
    )
    if isinstance(raw, dict):
        code = raw.get("code") or raw.get("status")
        message = str(raw.get("message") or raw.get("msg") or "")
        has_records = bool(find_first_list(raw))
        if code not in (None, 0, 1, 200, "0", "1", "200") and not has_records:
            raise ProviderError(message or f"API.cn 返回异常状态: {code}")

    records, raw_count = parse_apicn_day_records(raw, query_date, page)
    return records, raw_count, raw


def request_json(
    session: requests.Session,
    url: str,
    params: dict[str, Any],
    timeout: int,
    headers: dict[str, str] | None = None,
) -> Any:
    response = session.get(url, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        body = response.text.strip().replace("\n", " ")
        preview = body[:180] if body else "<empty body>"
        raise ProviderError(f"接口未返回 JSON: {preview}") from exc


def request_json_post(
    session: requests.Session,
    url: str,
    data: dict[str, str],
    headers: dict[str, str],
    timeout: int,
) -> Any:
    response = session.post(url, data=data, headers=headers, timeout=timeout)
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as exc:
        body = response.text.strip().replace("\n", " ")
        preview = body[:180] if body else "<empty body>"
        raise ProviderError(f"接口未返回 JSON: {preview}") from exc


def normalize_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def extract_label_value(lines: list[str], label: str) -> str | None:
    normalized_label = label.rstrip(":：")
    stop_labels = {
        "域名",
        "Whois服务器",
        "更新时间",
        "注册时间",
        "过期时间",
        "注册机构",
        "状态",
        "DNS",
        "备案信息",
        "注册人",
        "完整 WHOIS 信息",
    }
    for index, line in enumerate(lines):
        if line.rstrip(":：") == normalized_label:
            for value in lines[index + 1 :]:
                if value.startswith("·"):
                    continue
                if value.rstrip(":：") in stop_labels:
                    return None
                return value
    return None


def extract_section_items(lines: list[str], section_label: str) -> list[str]:
    normalized_label = section_label.rstrip(":：")
    items: list[str] = []
    in_section = False
    stop_labels = {
        "域名",
        "Whois服务器",
        "更新时间",
        "注册时间",
        "过期时间",
        "注册机构",
        "状态",
        "DNS",
        "备案信息",
        "注册人",
        "完整 WHOIS 信息",
    }
    for line in lines:
        if line.rstrip(":：") == normalized_label:
            in_section = True
            continue
        if not in_section:
            continue
        if line.rstrip(":：") in stop_labels:
            break
        if line.startswith("·"):
            items.append(line[1:].strip())
    return items


def extract_beian_fields(lines: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        start = next(index for index, line in enumerate(lines) if line.rstrip(":：") == "备案信息")
    except StopIteration:
        return fields

    index = start + 1
    while index < len(lines):
        line = lines[index]
        if not line.startswith("·"):
            index += 1
            continue

        key = line[1:].strip().rstrip(":：")
        if key == "未找到备案信息":
            fields["message"] = key
            break

        value = ""
        if index + 1 < len(lines):
            next_line = lines[index + 1]
            if not next_line.startswith("·") and next_line.rstrip(":：") not in {"完整 WHOIS 信息"}:
                value = next_line
        if key:
            fields[key] = value
        index += 2
    return fields


def parse_display_datetime(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()
    formats = (
        "%m/%d/%Y, %I:%M:%S %p",
        "%m/%d/%Y, %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.isoformat()
        except ValueError:
            continue
    return value


def is_expired(expiration_date: str | None) -> bool | None:
    if not expiration_date:
        return None
    try:
        parsed = datetime.fromisoformat(expiration_date)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed < datetime.now()
    return parsed < datetime.now(timezone.utc)


def parse_jyblog_text(domain: str, card_text: str, whois_text: str) -> QueryResult:
    card_lines = normalize_lines(card_text)
    raw = {"card_text": card_text, "whois_text": whois_text}

    if any(line in {"未注册", "不存在"} for line in card_lines):
        return QueryResult(
            domain=domain,
            status="not_found",
            provider="jyblog",
            raw=raw,
            registered=False,
            expired=None,
            error="域名未注册",
        )

    beian = extract_beian_fields(card_lines)
    icp = beian.get("许可证号")
    main_licence = beian.get("备案主体")
    unit = beian.get("单位名称")
    site_type = beian.get("单位性质")
    approved_at = beian.get("通过时间")

    expiration_date = parse_display_datetime(extract_label_value(card_lines, "过期时间"))
    creation_date = parse_display_datetime(extract_label_value(card_lines, "注册时间"))
    updated_date = parse_display_datetime(extract_label_value(card_lines, "更新时间"))
    has_icp = bool(icp and looks_like_icp_number(icp))

    return QueryResult(
        domain=domain,
        status="found" if has_icp else "not_found",
        provider="jyblog",
        raw=raw,
        registered=True,
        expired=is_expired(expiration_date),
        expiration_date=expiration_date,
        creation_date=creation_date,
        updated_date=updated_date,
        registrar=extract_label_value(card_lines, "注册机构"),
        whois_server=extract_label_value(card_lines, "Whois服务器"),
        domain_statuses=extract_section_items(card_lines, "状态"),
        name_servers=extract_section_items(card_lines, "DNS"),
        icp=icp,
        main_licence=main_licence,
        unit=unit,
        site_type=site_type,
        approved_at=approved_at,
        error=None if has_icp else beian.get("message") or "未找到备案信息",
    )


def query_jyblog_page(page: Any, domain: str, timeout: int) -> QueryResult:
    url = f"{JYBLOG_URL}#{quote(domain)}"
    try:
        page.goto("about:blank", timeout=timeout * 1000)
        page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
        page.wait_for_function(
            """() => {
                const card = document.querySelector('.whoiscard');
                return card && card.innerText && card.innerText.trim().length > 0;
            }""",
            timeout=timeout * 1000,
        )
        try:
            page.wait_for_function(
                """() => {
                    const card = document.querySelector('.whoiscard');
                    const text = card ? card.innerText : '';
                    return text.includes('备案信息') ||
                        text.includes('未注册') ||
                        text.includes('不存在') ||
                        text.startsWith('错误:');
                }""",
                timeout=timeout * 1000,
            )
        except PlaywrightTimeoutError:
            page.wait_for_timeout(1000)
        card_text = page.locator(".whoiscard").inner_text(timeout=timeout * 1000)
        try:
            whois_text = page.locator(".inner").inner_text(timeout=5000)
        except PlaywrightTimeoutError:
            whois_text = ""
        return parse_jyblog_text(domain, card_text, whois_text)
    except Exception as exc:
        return QueryResult(domain=domain, status="error", provider="jyblog", error=str(exc))


def parse_jyblog_whois_api(domain: str, raw: Any) -> QueryResult:
    if not isinstance(raw, dict):
        return QueryResult(
            domain=domain,
            status="unknown",
            provider="jyblog-whois-api",
            raw=raw,
            error="接口返回格式不是对象",
        )

    raw_text = json.dumps(raw, ensure_ascii=False).lower()
    not_found_signals = (
        "domain not found",
        "object does not exist",
        "no match",
        "not found",
        "未注册",
        "不存在",
    )
    domain_name = raw.get("Domain Name") or raw.get("Domain name")
    if not domain_name and any(signal in raw_text for signal in not_found_signals):
        return QueryResult(
            domain=domain,
            status="not_found",
            provider="jyblog-whois-api",
            raw=raw,
            registered=False,
            expired=None,
            error="域名未注册",
        )
    if not domain_name:
        return QueryResult(
            domain=domain,
            status="unknown",
            provider="jyblog-whois-api",
            raw=raw,
            error="WHOIS 返回中未找到域名字段",
        )

    expiration_date = parse_display_datetime(
        raw.get("Registry Expiry Date")
        or raw.get("Registry Expiry")
        or raw.get("Expiration Date")
        or raw.get("Expiration Time")
    )
    creation_date = parse_display_datetime(
        raw.get("Creation Date") or raw.get("Registration Time")
    )
    updated_date = parse_display_datetime(raw.get("Updated Date") or raw.get("Update Date"))
    statuses = [
        value
        for value in str(raw.get("Domain Status") or "").split()
        if value and not value.startswith("http")
    ]
    name_servers = [
        value
        for value in str(raw.get("Name Server") or "").split()
        if value
    ]

    return QueryResult(
        domain=domain,
        status="found",
        provider="jyblog-whois-api",
        raw=raw,
        registered=True,
        expired=is_expired(expiration_date),
        expiration_date=expiration_date,
        creation_date=creation_date,
        updated_date=updated_date,
        registrar=raw.get("Registrar") or raw.get("Sponsoring Registrar"),
        whois_server=raw.get("Registrar WHOIS Server"),
        domain_statuses=statuses or None,
        name_servers=name_servers or None,
    )


def query_jyblog_api_whois(
    session: requests.Session,
    domain: str,
    timeout: int,
    retries: int,
) -> QueryResult:
    for attempt in range(retries + 1):
        try:
            raw = request_json_post(
                session=session,
                url=JYBLOG_WHOIS_API,
                data={"domain": domain},
                headers=build_jyblog_api_headers(),
                timeout=timeout,
            )
            return parse_jyblog_whois_api(domain, raw)
        except (requests.RequestException, ProviderError) as exc:
            if attempt < retries:
                time.sleep(2)
                continue
            return QueryResult(
                domain=domain,
                status="error",
                provider="jyblog-whois-api",
                error=str(exc),
            )

    return QueryResult(
        domain=domain,
        status="error",
        provider="jyblog-whois-api",
        error="超过最大重试次数",
    )


def build_apihz_icp_url(base_url: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", APIHZ_ICP_PATH)


def discover_apihz_icp_url(
    session: requests.Session,
    timeout: int,
    configured_base_url: str | None,
) -> str:
    if configured_base_url:
        return build_apihz_icp_url(configured_base_url)

    try:
        raw = request_json(session, APIHZ_DISCOVERY_URL, params={}, timeout=timeout)
        if isinstance(raw, dict) and raw.get("code") == 200 and raw.get("api"):
            return build_apihz_icp_url(str(raw["api"]))
    except Exception as exc:
        print(f"提示：apihz 节点发现失败，将使用备用节点：{exc}")

    return build_apihz_icp_url(APIHZ_LAST_KNOWN_BASE_URL)


def extract_retry_after(raw: Any) -> int | None:
    if not isinstance(raw, dict):
        return None

    seconds = raw.get("s")
    if isinstance(seconds, int) and seconds > 0:
        return min(seconds, 120)

    message = str(raw.get("msg", ""))
    match = re.search(r"(\d+)\s*秒", message)
    if match:
        return min(int(match.group(1)), 120)
    return None


def generate_jyblog_nonce(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_jyblog_signature(
    nonce: str,
    timestamp: int | str,
    secret_key: str = JYBLOG_SECRET_KEY,
) -> str:
    payload = {"nonce": str(nonce), "timestamp": str(timestamp)}
    signing_text = "".join(key + payload[key] for key in sorted(payload)) + secret_key
    return hashlib.sha256(signing_text.encode("utf-8")).hexdigest()


def build_jyblog_api_headers(
    nonce: str | None = None,
    timestamp: int | None = None,
) -> dict[str, str]:
    nonce = nonce or generate_jyblog_nonce()
    timestamp = timestamp or int(time.time())
    return {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Origin": "https://who.jyblog.com",
        "Referer": "https://who.jyblog.com/",
        "User-Agent": "Mozilla/5.0 icp-query/1.0",
        "X-Requested-With": "XMLHttpRequest",
        "nonce": nonce,
        "timestamp": str(timestamp),
        "signature": generate_jyblog_signature(nonce, timestamp),
    }


def looks_like_icp_number(value: Any) -> bool:
    if value is None:
        return False

    text = str(value).strip()
    if not text or contains_failure_signal(text):
        return False
    if re.search(r"ICP", text, flags=re.IGNORECASE):
        return True

    # Some APIs return value-added telecom record numbers without the literal "ICP".
    # Example: 粤B2-20090059-5.
    return re.search(r"^[\u4e00-\u9fff][A-Z]\d?-\d{6,}(?:-\d+)?$", text) is not None


def join_message(*values: Any) -> str:
    return " ".join(str(value) for value in values if value is not None)


def contains_failure_signal(*values: Any) -> bool:
    text = join_message(*values)
    failure_words = ("查询失败", "没有备案", "失败", *TRANSIENT_ERROR_WORDS)
    return any(word in text for word in failure_words)


def is_no_record_message(*values: Any) -> bool:
    text = join_message(*values)
    return any(word in text for word in NO_RECORD_WORDS) and "查询失败或没有备案" not in text


def is_transient_error_message(*values: Any) -> bool:
    text = join_message(*values)
    return any(word in text for word in TRANSIENT_ERROR_WORDS)


def query_apihz(
    session: requests.Session,
    url: str,
    domain: str,
    timeout: int,
    retries: int,
    api_id: str,
    api_key: str,
) -> QueryResult:
    params = {"id": api_id, "key": api_key, "domain": domain}

    for attempt in range(retries + 1):
        raw = request_json(session, url, params=params, timeout=timeout)
        if not isinstance(raw, dict):
            return QueryResult(
                domain=domain,
                status="unknown",
                provider="apihz",
                raw=raw,
                error="接口返回格式不是对象",
            )

        code = raw.get("code")
        icp = raw.get("icp")
        if code == 200 and looks_like_icp_number(icp) and not contains_failure_signal(
            raw.get("icp"),
            raw.get("unit"),
            raw.get("type"),
            raw.get("time"),
            raw.get("msg"),
        ):
            return QueryResult(
                domain=domain,
                status="found",
                provider="apihz",
                raw=raw,
                icp=str(icp),
                unit=raw.get("unit"),
                site_type=raw.get("type"),
                approved_at=raw.get("time"),
            )

        message = str(raw.get("msg") or raw.get("message") or "")
        if code == 200 and contains_failure_signal(
            raw.get("icp"),
            raw.get("unit"),
            raw.get("type"),
            raw.get("time"),
            message,
        ):
            if is_transient_error_message(message) and attempt < retries:
                time.sleep(2)
                continue
            if is_no_record_message(message):
                return QueryResult(
                    domain=domain,
                    status="not_found",
                    provider="apihz",
                    raw=raw,
                    error=message,
                )
            return QueryResult(
                domain=domain,
                status="unknown",
                provider="apihz",
                raw=raw,
                error=message or "接口返回结果不确定",
            )

        retry_after = extract_retry_after(raw)
        is_rate_limited = retry_after is not None or "频次" in str(raw.get("msg", ""))
        if is_rate_limited and attempt < retries:
            wait_seconds = retry_after or 10
            print(f"  -> 接口频控，等待 {wait_seconds} 秒后重试...")
            time.sleep(wait_seconds)
            continue

        if code == 400 and is_rate_limited:
            return QueryResult(
                domain=domain,
                status="error",
                provider="apihz",
                raw=raw,
                error=f"接口频控: {message}",
            )
        if code == 400 and "重试" in message and attempt < retries:
            time.sleep(2)
            continue
        if code == 400 and "重试" in message:
            return QueryResult(
                domain=domain,
                status="error",
                provider="apihz",
                raw=raw,
                error=message,
            )
        if code == 400 and message:
            if is_no_record_message(message):
                return QueryResult(
                    domain=domain,
                    status="not_found",
                    provider="apihz",
                    raw=raw,
                    error=message,
                )
            if contains_failure_signal(message):
                return QueryResult(
                    domain=domain,
                    status="unknown",
                    provider="apihz",
                    raw=raw,
                    error=message,
                )
            return QueryResult(
                domain=domain,
                status="not_found",
                provider="apihz",
                raw=raw,
                error=message,
            )

        return QueryResult(
            domain=domain,
            status="unknown",
            provider="apihz",
            raw=raw,
            error=message or "接口返回结果不确定",
        )

    return QueryResult(
        domain=domain,
        status="error",
        provider="apihz",
        error="超过最大重试次数",
    )


def query_uomg(
    session: requests.Session,
    domain: str,
    timeout: int,
    retries: int,
) -> QueryResult:
    for attempt in range(retries + 1):
        try:
            raw = request_json(session, UOMG_URL, params={"domain": domain}, timeout=timeout)
            break
        except Exception as exc:
            if attempt < retries:
                time.sleep(2)
                continue
            return QueryResult(
                domain=domain,
                status="error",
                provider="uomg",
                error=str(exc),
            )

    if isinstance(raw, dict) and raw.get("error"):
        return QueryResult(
            domain=domain,
            status="error",
            provider="uomg",
            raw=raw,
            error=str(raw["error"]),
        )

    result_text = json.dumps(raw, ensure_ascii=False).lower()
    has_icp_signal = "备案" in result_text or "icp" in result_text or (
        isinstance(raw, dict) and raw.get("code") == 1
    )
    return QueryResult(
        domain=domain,
        status="found" if has_icp_signal else "not_found",
        provider="uomg",
        raw=raw,
        icp=extract_first_icp_number(raw),
    )


def query_jyblog_api_beian(
    session: requests.Session,
    domain: str,
    timeout: int,
    retries: int,
) -> QueryResult:
    for attempt in range(retries + 1):
        try:
            raw = request_json_post(
                session=session,
                url=JYBLOG_BEIAN_API,
                data={"domain": domain},
                headers=build_jyblog_api_headers(),
                timeout=timeout,
            )
            break
        except (requests.RequestException, ProviderError) as exc:
            if attempt < retries:
                time.sleep(2)
                continue
            return QueryResult(
                domain=domain,
                status="error",
                provider="jyblog-api",
                error=str(exc),
            )

    if not isinstance(raw, dict):
        return QueryResult(
            domain=domain,
            status="unknown",
            provider="jyblog-api",
            raw=raw,
            error="接口返回格式不是对象",
        )

    if raw.get("error"):
        message = str(raw.get("message") or raw.get("msg") or raw.get("error"))
        return QueryResult(
            domain=domain,
            status="unknown",
            provider="jyblog-api",
            raw=raw,
            error=message,
        )

    if not raw.get("domain"):
        return QueryResult(
            domain=domain,
            status="not_found",
            provider="jyblog-api",
            raw=raw,
            error="未找到备案信息",
        )

    icp = raw.get("serviceLicence")
    has_icp = looks_like_icp_number(icp)
    return QueryResult(
        domain=domain,
        status="found" if has_icp else "unknown",
        provider="jyblog-api",
        raw=raw,
        icp=str(icp) if icp is not None else None,
        main_licence=raw.get("mainLicence"),
        unit=raw.get("unitName"),
        site_type=raw.get("natureName"),
        approved_at=raw.get("updateRecordTime"),
        error=None if has_icp else "接口返回备案记录但许可证号格式异常",
    )


def extract_first_icp_number(raw: Any) -> str | None:
    text = json.dumps(raw, ensure_ascii=False)
    match = re.search(r"[\u4e00-\u9fff]ICP[备证]?\d+(?:-\d+)?", text, flags=re.IGNORECASE)
    return match.group(0) if match else None


def query_domain(
    session: requests.Session,
    domain: str,
    provider: str,
    apihz_url: str,
    timeout: int,
    retries: int,
    api_id: str,
    api_key: str,
) -> QueryResult:
    try:
        if provider == "jyblog-api":
            return query_jyblog_api_beian(session, domain, timeout, retries)
        if provider == "apihz":
            return query_apihz(session, apihz_url, domain, timeout, retries, api_id, api_key)
        if provider == "uomg":
            return query_uomg(session, domain, timeout, retries)
    except requests.RequestException as exc:
        return QueryResult(domain=domain, status="error", provider=provider, error=str(exc))
    except ProviderError as exc:
        return QueryResult(domain=domain, status="error", provider=provider, error=str(exc))

    return QueryResult(domain=domain, status="error", provider=provider, error="未知 Provider")


def create_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json,text/plain,*/*",
            "User-Agent": "Mozilla/5.0 icp-query/1.0",
        }
    )
    return session


def make_nonmatching_registered_result(whois_result: QueryResult) -> QueryResult:
    return QueryResult(
        domain=whois_result.domain,
        status="not_found",
        provider=whois_result.provider,
        raw={"whois": asdict(whois_result)},
        registered=whois_result.registered,
        expired=whois_result.expired,
        expiration_date=whois_result.expiration_date,
        creation_date=whois_result.creation_date,
        updated_date=whois_result.updated_date,
        registrar=whois_result.registrar,
        whois_server=whois_result.whois_server,
        domain_statuses=whois_result.domain_statuses,
        name_servers=whois_result.name_servers,
        icp=whois_result.icp,
        main_licence=whois_result.main_licence,
        unit=whois_result.unit,
        site_type=whois_result.site_type,
        approved_at=whois_result.approved_at,
        error="域名已注册，不符合未注册目标",
    )


def merge_unregistered_whois_and_icp(
    whois_result: QueryResult,
    icp_result: QueryResult,
) -> QueryResult:
    is_match = icp_result.status == "found" and looks_like_icp_number(icp_result.icp)
    return QueryResult(
        domain=whois_result.domain,
        status="found" if is_match else icp_result.status,
        provider=f"{whois_result.provider}+{icp_result.provider}",
        raw={
            "whois": asdict(whois_result),
            "icp": asdict(icp_result),
        },
        registered=False,
        expired=None,
        icp=icp_result.icp,
        main_licence=icp_result.main_licence,
        unit=icp_result.unit,
        site_type=icp_result.site_type,
        approved_at=icp_result.approved_at,
        error=None if is_match else icp_result.error or "未注册，但未查到备案",
    )


def merge_unregistered_whois_and_history(
    whois_result: QueryResult,
    history_result: QueryResult,
) -> QueryResult:
    return QueryResult(
        domain=whois_result.domain,
        status="found",
        provider=f"{whois_result.provider}+{history_result.provider}",
        raw={
            "whois": asdict(whois_result),
            "history": asdict(history_result),
        },
        registered=False,
        expired=None,
        icp=history_result.icp,
        main_licence=history_result.main_licence,
        unit=history_result.unit,
        site_type=history_result.site_type,
        approved_at=history_result.approved_at,
    )


def print_result(result: QueryResult) -> None:
    if result.status == "found":
        details = "，".join(
            value
            for value in (result.icp, result.unit, result.approved_at)
            if value
        )
        print(f"  -> 查到备案: {details or '见 raw 数据'}")
        if result.expiration_date:
            print(f"     域名过期时间: {result.expiration_date}")
    elif result.registered is False:
        print(f"  -> 域名未注册: {result.error or 'WHOIS 显示未注册'}")
    elif result.status == "not_found":
        print(f"  -> 未查询到备案记录: {result.error or '接口返回为空'}")
        if result.expiration_date:
            print(f"     域名过期时间: {result.expiration_date}")
    elif result.status == "unknown":
        print(f"  -> 查询结果不确定: {result.error or '接口返回结果不确定'}")
    else:
        print(f"  -> 查询失败: {result.error or '未知错误'}")


def print_target_result(result: QueryResult) -> None:
    if result.status == "found" and result.registered is False:
        details = "，".join(
            value
            for value in (result.icp, result.unit, result.approved_at)
            if value
        )
        print(f"  -> 命中目标：未注册 + 查到备案: {details or '见 raw 数据'}")
        return

    if result.registered is True:
        print(f"  -> 跳过：{result.error or '域名已注册'}")
        if result.expiration_date:
            print(f"     域名过期时间: {result.expiration_date}")
        return

    if result.registered is False and result.status in {"not_found", "unknown", "error"}:
        print(f"  -> 未命中：域名未注册，但备案补查结果为 {result.status}: {result.error}")
        return

    print_result(result)


def write_results(
    path: str,
    results: list[QueryResult],
    metadata: dict[str, Any] | None = None,
) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summarize(results),
        "results": [asdict(result) for result in results],
    }
    if metadata:
        payload["metadata"] = metadata
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)


def read_json_file(path: str) -> Any:
    input_path = Path(path)
    if not input_path.exists():
        return None
    with open(input_path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_scan_state(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    raw = read_json_file(path)
    return raw if isinstance(raw, dict) else {}


def write_scan_state(
    path: str | None,
    state: dict[str, Any],
) -> None:
    if not path:
        return
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        **state,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)


def append_matches_file(
    path: str | None,
    matches: list[QueryResult],
    metadata: dict[str, Any],
) -> None:
    if not path:
        return

    existing = read_json_file(path)
    existing_results = []
    if isinstance(existing, dict) and isinstance(existing.get("results"), list):
        existing_results = existing["results"]
    elif isinstance(existing, list):
        existing_results = existing

    by_domain: dict[str, dict[str, Any]] = {}
    for item in existing_results:
        if isinstance(item, dict) and item.get("domain"):
            by_domain[str(item["domain"])] = item
    for result in matches:
        by_domain[result.domain] = asdict(result)

    results = list(by_domain.values())
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summarize_dict_results(results),
        "metadata": metadata,
        "results": results,
    }
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)


def summarize(results: list[QueryResult]) -> dict[str, int]:
    summary = {"total": len(results), "found": 0, "not_found": 0, "error": 0, "unknown": 0}
    for result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    return summary


def summarize_dict_results(results: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(results), "found": 0, "not_found": 0, "error": 0, "unknown": 0}
    for result in results:
        status = str(result.get("status") or "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary


def print_summary(summary: dict[str, int], found_label: str = "查到备案") -> None:
    print(
        f"总数 {summary['total']}，{found_label} {summary['found']}，"
        f"未查到 {summary['not_found']}，不确定 {summary['unknown']}，"
        f"失败 {summary['error']}。"
    )


def scan_apicn_day_source(
    args: argparse.Namespace,
    session: requests.Session,
    tlds: tuple[str, ...],
    scan_state: dict[str, Any],
    deadline: float | None,
) -> tuple[list[QueryResult], list[QueryResult], int, bool, dict[str, Any]]:
    if not args.apicn_base_url:
        raise ProviderError("缺少 APICN_BASE_URL。请在 GitHub Secrets 中配置 APICN_BASE_URL。")
    if not args.apicn_token:
        raise ProviderError("缺少 APICN_TOKEN。请在 GitHub Secrets 中配置 APICN_TOKEN。")

    start_date = parse_date_arg(args.apicn_start_date, "apicn-start-date")
    end_date = parse_date_arg(args.apicn_end_date, "apicn-end-date") or datetime.now().date()
    if start_date is None:
        start_date = parse_date_arg(APICN_DEFAULT_START_DATE, "apicn-start-date")
    if start_date is None:
        raise ProviderError("apicn-start-date 不能为空")
    if end_date < start_date:
        raise ProviderError("apicn-end-date 不能早于 apicn-start-date")

    state_date = parse_date_arg(str(scan_state.get("apicn_date") or ""), "state.apicn_date")
    current_date = max(state_date or start_date, start_date)
    page = max(int(scan_state.get("apicn_page") or 1), 1)
    offset = max(int(scan_state.get("apicn_offset") or 0), 0)
    page_size = normalize_page_size(args.apicn_page_size)

    all_checked_results: list[QueryResult] = []
    matched_results: list[QueryResult] = []
    run_scanned = 0
    stopped_by_runtime = False
    stopped_by_limit = False
    previous_scanned_total = int(scan_state.get("scanned_domains_total") or 0)

    def save_state(
        query_date: date,
        current_page: int,
        current_offset: int,
        raw_count: int | None = None,
    ) -> None:
        write_scan_state(
            args.state_file,
            {
                "mode": "apicn-day",
                "target": args.target,
                "apicn_date": query_date.isoformat(),
                "apicn_page": current_page,
                "apicn_offset": current_offset,
                "apicn_start_date": start_date.isoformat(),
                "apicn_end_date": end_date.isoformat(),
                "apicn_page_size": page_size,
                "tlds": list(tlds),
                "scanned_domains_total": previous_scanned_total + run_scanned,
                "last_run_scanned": run_scanned,
                "last_run_matched": len(matched_results),
                "last_page_raw_count": raw_count,
                "stopped_by_runtime": stopped_by_runtime,
                "stopped_by_limit": stopped_by_limit,
            },
        )

    print("历史备案候选接口: API.cn /day/")
    print(f"历史备案日期范围: {start_date.isoformat()} -> {end_date.isoformat()}")
    print(f"历史备案续跑位置: {current_date.isoformat()} 第 {page} 页 offset {offset}\n")

    while current_date <= end_date:
        if deadline and time.monotonic() >= deadline:
            stopped_by_runtime = True
            save_state(current_date, page, offset)
            print("  -> 达到本次运行时间上限，保存状态后退出。")
            break
        if args.limit and run_scanned >= args.limit:
            stopped_by_limit = True
            save_state(current_date, page, offset)
            print("  -> 达到本次运行数量上限，保存状态后退出。")
            break

        print(f"拉取历史备案候选: {current_date.isoformat()} 第 {page} 页")
        for attempt in range(max(args.retries, 0) + 1):
            try:
                history_records, raw_count, _raw = query_apicn_day_page(
                    session=session,
                    base_url=args.apicn_base_url,
                    token=args.apicn_token,
                    query_date=current_date.isoformat(),
                    page=page,
                    page_size=page_size,
                    timeout=args.timeout,
                )
                break
            except (requests.RequestException, ProviderError) as exc:
                if attempt < max(args.retries, 0):
                    time.sleep(2)
                    continue
                raise ProviderError(
                    f"API.cn {current_date.isoformat()} 第 {page} 页拉取失败: {exc}"
                ) from exc

        if not args.all_tlds:
            history_records = [
                record for record in history_records if record.domain.endswith(tlds)
            ]

        if offset >= len(history_records):
            is_last_page = raw_count < page_size
            if is_last_page:
                current_date += timedelta(days=1)
                page = 1
            else:
                page += 1
            offset = 0
            if current_date <= end_date:
                save_state(current_date, page, offset, raw_count)
            continue

        for index in range(offset, len(history_records)):
            if deadline and time.monotonic() >= deadline:
                stopped_by_runtime = True
                save_state(current_date, page, index, raw_count)
                print("  -> 达到本次运行时间上限，保存状态后退出。")
                return (
                    all_checked_results,
                    matched_results,
                    run_scanned,
                    stopped_by_runtime,
                    {
                        "history_source": "apicn-day",
                        "history_stopped_by_limit": stopped_by_limit,
                    },
                )
            if args.limit and run_scanned >= args.limit:
                stopped_by_limit = True
                save_state(current_date, page, index, raw_count)
                print("  -> 达到本次运行数量上限，保存状态后退出。")
                return (
                    all_checked_results,
                    matched_results,
                    run_scanned,
                    stopped_by_runtime,
                    {
                        "history_source": "apicn-day",
                        "history_stopped_by_limit": stopped_by_limit,
                    },
                )

            history_result = history_records[index]
            domain = history_result.domain
            print(
                f"[{run_scanned + 1}] 历史备案候选: {domain} "
                f"({current_date.isoformat()} p{page}#{index})"
            )
            whois_result = query_jyblog_api_whois(
                session=session,
                domain=domain,
                timeout=args.timeout,
                retries=max(args.retries, 0),
            )

            if whois_result.registered is False:
                result = merge_unregistered_whois_and_history(whois_result, history_result)
            elif whois_result.status in {"error", "unknown"}:
                result = whois_result
            else:
                result = make_nonmatching_registered_result(whois_result)
                result.raw = {
                    "whois": asdict(whois_result),
                    "history": asdict(history_result),
                }
                result.icp = history_result.icp
                result.main_licence = history_result.main_licence
                result.unit = history_result.unit
                result.site_type = history_result.site_type
                result.approved_at = history_result.approved_at

            all_checked_results.append(result)
            if result.status == "found" and result.registered is False:
                matched_results.append(result)
            print_target_result(result)

            run_scanned += 1
            save_state(current_date, page, index + 1, raw_count)

            if index < len(history_records) - 1 and args.delay > 0:
                time.sleep(args.delay)

        is_last_page = raw_count < page_size
        if is_last_page:
            current_date += timedelta(days=1)
            page = 1
        else:
            page += 1
        offset = 0
        if current_date <= end_date:
            save_state(current_date, page, offset, raw_count)

    return (
        all_checked_results,
        matched_results,
        run_scanned,
        stopped_by_runtime,
        {
            "history_source": "apicn-day",
            "history_start_date": start_date.isoformat(),
            "history_end_date": end_date.isoformat(),
            "history_last_date": min(current_date, end_date).isoformat(),
            "history_page_size": page_size,
            "history_stopped_by_limit": stopped_by_limit,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="批量查询域名 WHOIS、过期时间和 ICP 备案记录。"
    )
    parser.add_argument("domains", nargs="*", help="要查询的域名或 URL。")
    parser.add_argument(
        "-f",
        "--file",
        help="域名列表文件，每行一个域名；空行和 # 开头的行会被忽略。",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"结果 JSON 文件路径，默认：{DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="按 a-z0-9 组合生成候选域名；默认从 4 字符 label 开始。",
    )
    parser.add_argument(
        "--apicn-day-source",
        action="store_true",
        help="从 API.cn /day/ 历史备案日期库拉取候选域名，再查询当前 WHOIS。",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="生成模式的最短 label 长度，默认：4。",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=4,
        help="生成模式的最长 label 长度，默认：4。",
    )
    parser.add_argument(
        "--alphabet",
        default=GENERATED_ALPHABET,
        help="生成模式使用的字符集，只能包含 a-z0-9；纯数字可设置为 0123456789。",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="生成模式或历史备案模式本次最多查询多少个候选域名；首次试跑建议设置。",
    )
    parser.add_argument(
        "--max-runtime-seconds",
        type=int,
        help="本次运行的最长扫描秒数；到时会保存状态后正常退出。",
    )
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help=f"生成模式或历史备案模式续跑状态文件，默认：{DEFAULT_STATE_FILE}。",
    )
    parser.add_argument(
        "--matches-file",
        default=DEFAULT_MATCHES_FILE,
        help=f"生成模式或历史备案模式累计命中结果文件，默认：{DEFAULT_MATCHES_FILE}。",
    )
    parser.add_argument(
        "--start-after",
        help="生成模式从某个 label 后继续，例如 a0zz 或 a0zz.xyz。",
    )
    parser.add_argument(
        "--provider",
        choices=("jyblog", "jyblog-api", "apihz", "uomg"),
        default="jyblog",
        help="查询来源，默认使用 who.jyblog.com 前端页面解析；jyblog-api 只查备案 API。",
    )
    parser.add_argument(
        "--target",
        choices=(TARGET_ALL, TARGET_UNREGISTERED_WITH_ICP),
        default=TARGET_ALL,
        help="筛选目标；unregistered-with-icp 只保存未注册且查到备案的域名。",
    )
    parser.add_argument(
        "--icp-provider",
        choices=("jyblog-api", "apihz", "uomg"),
        default="jyblog-api",
        help="target=unregistered-with-icp 时的备案补查来源，默认：jyblog-api。",
    )
    parser.add_argument(
        "--all-tlds",
        action="store_true",
        help="不过滤后缀，查询输入中的全部域名。",
    )
    parser.add_argument(
        "--tlds",
        default=",".join(SUPPORTED_TLDS),
        help="逗号分隔的后缀过滤列表，默认：.xyz,.icu,.top。",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"每次查询后的等待秒数，默认：{DEFAULT_DELAY}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"单次请求超时秒数，默认：{DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"遇到网络错误或频控时的重试次数，默认：{DEFAULT_RETRIES}",
    )
    parser.add_argument(
        "--apihz-id",
        default=os.getenv("APIHZ_ID", APIHZ_PUBLIC_ID),
        help="接口盒子 ID，也可用环境变量 APIHZ_ID 设置。",
    )
    parser.add_argument(
        "--apihz-key",
        default=os.getenv("APIHZ_KEY", APIHZ_PUBLIC_KEY),
        help="接口盒子 KEY，也可用环境变量 APIHZ_KEY 设置。",
    )
    parser.add_argument(
        "--apihz-base-url",
        default=os.getenv("APIHZ_BASE_URL"),
        help="手动指定接口盒子 API 根地址；默认自动发现当前可用节点。",
    )
    parser.add_argument(
        "--apicn-base-url",
        default=os.getenv("APICN_BASE_URL"),
        help="API.cn 分配的 API 根地址，也可用环境变量 APICN_BASE_URL 设置。",
    )
    parser.add_argument(
        "--apicn-token",
        default=os.getenv("APICN_TOKEN"),
        help="API.cn token，也可用环境变量 APICN_TOKEN 设置。",
    )
    parser.add_argument(
        "--apicn-start-date",
        default=os.getenv("APICN_START_DATE", APICN_DEFAULT_START_DATE),
        help=f"API.cn 历史备案起始日期，格式 YYYY-MM-DD，默认：{APICN_DEFAULT_START_DATE}。",
    )
    parser.add_argument(
        "--apicn-end-date",
        default=os.getenv("APICN_END_DATE"),
        help="API.cn 历史备案结束日期，格式 YYYY-MM-DD；默认到今天。",
    )
    parser.add_argument(
        "--apicn-page-size",
        type=int,
        default=int(os.getenv("APICN_PAGE_SIZE", str(APICN_MAX_PAGE_SIZE))),
        help=f"API.cn /day/ 每页数量，最大 {APICN_MAX_PAGE_SIZE}。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只解析并展示将要查询的域名，不发起网络请求。",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="使用 jyblog provider 时显示浏览器窗口，便于调试。",
    )
    parser.add_argument(
        "--strict-exit",
        action="store_true",
        help="严格退出码：存在 unknown 结果时也返回非 0；默认只在 error 时返回非 0。",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.generate and args.apicn_day_source:
        print("--generate 和 --apicn-day-source 不能同时使用。")
        return 2
    if args.apicn_day_source:
        if args.state_file == DEFAULT_STATE_FILE:
            args.state_file = DEFAULT_APICN_STATE_FILE
        if args.matches_file == DEFAULT_MATCHES_FILE:
            args.matches_file = DEFAULT_APICN_MATCHES_FILE

    started_monotonic = time.monotonic()
    deadline = (
        started_monotonic + args.max_runtime_seconds
        if args.max_runtime_seconds and args.max_runtime_seconds > 0
        else None
    )
    tlds = tuple(tld.strip().lower() for tld in args.tlds.split(",") if tld.strip())
    scan_state = load_scan_state(args.state_file) if (args.generate or args.apicn_day_source) else {}
    state_start_after = scan_state.get("last_domain") or scan_state.get("last_label")
    effective_start_after = args.start_after or state_start_after
    if args.apicn_day_source:
        domains = []
    elif args.generate:
        try:
            generated_alphabet = normalize_generated_alphabet(args.alphabet)
        except ValueError as exc:
            print(f"生成参数错误: {exc}")
            return 2
        if args.limit is None:
            total = generated_domain_count(
                tlds,
                args.min_length,
                args.max_length,
                alphabet=generated_alphabet,
            )
            print(
                "生成模式需要指定 --limit 作为本次运行上限；"
                f"当前长度范围预计候选 {total} 个。"
            )
            return 2
        try:
            domains = build_generated_domains(
                tlds=tlds,
                min_length=args.min_length,
                max_length=args.max_length,
                limit=args.limit,
                start_after=effective_start_after,
                alphabet=generated_alphabet,
            )
        except ValueError as exc:
            print(f"生成参数错误: {exc}")
            return 2
    else:
        generated_alphabet = normalize_generated_alphabet(args.alphabet)
        domains = load_domains(args.file, args.domains)
        if not args.all_tlds:
            domains = filter_domains(domains, tlds)

    if not domains and not args.apicn_day_source:
        print("没有可查询的域名。请检查输入文件、命令行参数或后缀过滤条件。")
        return 2

    print("=== 过期域名 ICP 备案查询脚本 ===")
    print(f"开始时间: {datetime.now()}")
    print(f"查询接口: {'apicn-day + jyblog-whois-api' if args.apicn_day_source else args.provider}")
    print(f"筛选目标: {args.target}")
    if not args.apicn_day_source:
        print(f"域名数量: {len(domains)}")
    if args.apicn_day_source:
        print("候选来源: API.cn 历史备案日期库")
        if deadline:
            print(f"本次最长扫描秒数: {args.max_runtime_seconds}")
        if args.limit:
            print(f"本次最多扫描候选: {args.limit}")
        print(f"状态文件: {Path(args.state_file).resolve()}")
        print(f"累计命中结果: {Path(args.matches_file).resolve()}")
    elif args.generate:
        print(
            "生成模式: "
            f"字符集 {generated_alphabet}，长度 {args.min_length}-{args.max_length}，"
            f"本次上限 {args.limit}"
        )
        if effective_start_after:
            print(f"续跑起点: {effective_start_after}")
        if deadline:
            print(f"本次最长扫描秒数: {args.max_runtime_seconds}")
        print(f"状态文件: {Path(args.state_file).resolve()}")
        print(f"累计命中结果: {Path(args.matches_file).resolve()}")
    print(f"结果文件: {Path(args.output).resolve()}\n")

    uses_apihz = args.provider == "apihz" or (
        args.target == TARGET_UNREGISTERED_WITH_ICP and args.icp_provider == "apihz"
    )
    if uses_apihz and (
        args.apihz_id == APIHZ_PUBLIC_ID or args.apihz_key == APIHZ_PUBLIC_KEY
    ):
        print("提示：当前使用 apihz 公共试用 ID/KEY，可能触发共享频控。")
        print("      建议设置自己的 APIHZ_ID 和 APIHZ_KEY 后再批量运行。\n")

    if args.dry_run:
        if args.apicn_day_source:
            print("API.cn 历史备案模式 dry-run：参数解析成功，不发起网络请求。")
            return 0
        for domain in domains:
            print(f"将查询: {domain}")
        return 0

    if args.target == TARGET_UNREGISTERED_WITH_ICP:
        session = create_http_session()
        apihz_url = ""
        if args.apicn_day_source:
            print("备案证明来源: API.cn 历史备案日期库\n")
        elif args.icp_provider == "apihz":
            apihz_url = discover_apihz_icp_url(
                session=session,
                timeout=args.timeout,
                configured_base_url=args.apihz_base_url,
            )
            print(f"备案补查节点: {apihz_url}\n")
        else:
            print(f"备案补查接口: {args.icp_provider}\n")

        all_checked_results: list[QueryResult] = []
        matched_results: list[QueryResult] = []
        stopped_by_runtime = False
        run_scanned = 0
        previous_scanned_total = int(scan_state.get("scanned_domains_total") or 0)
        metadata_extra: dict[str, Any] = {}

        if args.apicn_day_source:
            try:
                (
                    all_checked_results,
                    matched_results,
                    run_scanned,
                    stopped_by_runtime,
                    metadata_extra,
                ) = scan_apicn_day_source(
                    args=args,
                    session=session,
                    tlds=tlds,
                    scan_state=scan_state,
                    deadline=deadline,
                )
            except ProviderError as exc:
                print(f"历史备案候选拉取失败: {exc}")
                return 1
        elif args.generate:
            print("WHOIS 查询接口: jyblog-whois-api\n")
            for index, domain in enumerate(domains, start=1):
                if deadline and time.monotonic() >= deadline:
                    stopped_by_runtime = True
                    print("  -> 达到本次运行时间上限，保存状态后退出。")
                    break

                print(f"[{index}/{len(domains)}] 查询: {domain}")
                whois_result = query_jyblog_api_whois(
                    session=session,
                    domain=domain,
                    timeout=args.timeout,
                    retries=max(args.retries, 0),
                )

                if whois_result.registered is False:
                    print("  -> WHOIS 显示未注册，开始备案补查...")
                    icp_result = query_domain(
                        session=session,
                        domain=domain,
                        provider=args.icp_provider,
                        apihz_url=apihz_url,
                        timeout=args.timeout,
                        retries=max(args.retries, 0),
                        api_id=args.apihz_id,
                        api_key=args.apihz_key,
                    )
                    result = merge_unregistered_whois_and_icp(whois_result, icp_result)
                elif whois_result.status == "error":
                    result = whois_result
                elif whois_result.status == "unknown":
                    result = whois_result
                else:
                    result = make_nonmatching_registered_result(whois_result)

                all_checked_results.append(result)
                if result.status == "found" and result.registered is False:
                    matched_results.append(result)
                print_target_result(result)
                run_scanned += 1
                write_scan_state(
                    args.state_file,
                    {
                        "mode": "generate",
                        "target": args.target,
                        "last_domain": domain,
                        "last_label": domain_label(domain),
                        "min_length": args.min_length,
                        "max_length": args.max_length,
                        "alphabet": generated_alphabet,
                        "tlds": list(tlds),
                        "limit": args.limit,
                        "scanned_domains_total": previous_scanned_total + run_scanned,
                        "last_run_scanned": run_scanned,
                        "last_run_matched": len(matched_results),
                        "stopped_by_runtime": False,
                    },
                )

                if index < len(domains) and args.delay > 0:
                    time.sleep(args.delay)
        else:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=not args.headed)
                page = browser.new_page()
                try:
                    for index, domain in enumerate(domains, start=1):
                        print(f"[{index}/{len(domains)}] 查询: {domain}")
                        whois_result = query_jyblog_page(page, domain, args.timeout)

                        if whois_result.registered is False:
                            print("  -> WHOIS 显示未注册，开始备案补查...")
                            icp_result = query_domain(
                                session=session,
                                domain=domain,
                                provider=args.icp_provider,
                                apihz_url=apihz_url,
                                timeout=args.timeout,
                                retries=max(args.retries, 0),
                                api_id=args.apihz_id,
                                api_key=args.apihz_key,
                            )
                            result = merge_unregistered_whois_and_icp(whois_result, icp_result)
                        elif whois_result.status == "error":
                            result = whois_result
                        else:
                            result = make_nonmatching_registered_result(whois_result)

                        all_checked_results.append(result)
                        if result.status == "found" and result.registered is False:
                            matched_results.append(result)
                        print_target_result(result)

                        if index < len(domains) and args.delay > 0:
                            time.sleep(args.delay)
                finally:
                    browser.close()

        checked_summary = summarize(all_checked_results)
        metadata = {
            "target": args.target,
            "candidate_source": (
                "apicn-day"
                if args.apicn_day_source
                else "generated"
                if args.generate
                else "input"
            ),
            "whois_provider": "jyblog-whois-api" if (args.generate or args.apicn_day_source) else "jyblog",
            "icp_provider": None if args.apicn_day_source else args.icp_provider,
            "scanned_domains": run_scanned if args.apicn_day_source else len(domains),
            "checked_summary": checked_summary,
            "saved_results": "matches_only",
            "generated": args.generate,
            "apicn_day_source": args.apicn_day_source,
            "generate_min_length": args.min_length if args.generate else None,
            "generate_max_length": args.max_length if args.generate else None,
            "generate_alphabet": generated_alphabet if args.generate else None,
            "generate_limit": args.limit if args.generate else None,
            "generate_start_after": effective_start_after if args.generate else None,
            "run_scanned": run_scanned if (args.generate or args.apicn_day_source) else len(all_checked_results),
            "stopped_by_runtime": stopped_by_runtime,
        }
        metadata.update(metadata_extra)
        if args.generate or args.apicn_day_source:
            append_matches_file(args.matches_file, matched_results, metadata)
        if args.generate:
            last_domain = all_checked_results[-1].domain if all_checked_results else None
            if last_domain:
                write_scan_state(
                    args.state_file,
                    {
                        "mode": "generate",
                        "target": args.target,
                        "last_domain": last_domain,
                        "last_label": domain_label(last_domain),
                        "min_length": args.min_length,
                        "max_length": args.max_length,
                        "alphabet": generated_alphabet,
                        "tlds": list(tlds),
                        "limit": args.limit,
                        "scanned_domains_total": previous_scanned_total + run_scanned,
                        "last_run_scanned": run_scanned,
                        "last_run_matched": len(matched_results),
                        "stopped_by_runtime": stopped_by_runtime,
                    },
                )
        write_results(
            args.output,
            matched_results,
            metadata=metadata,
        )
        print("\n查询完成！")
        print(f"扫描 {len(all_checked_results)} 个域名，命中目标 {len(matched_results)} 个。")
        print_summary(checked_summary, found_label="命中")
        if args.generate or args.apicn_day_source:
            print(f"续跑状态已保存到 {args.state_file}")
            print(f"累计命中结果已保存到 {args.matches_file}")
        print(f"命中结果已保存到 {args.output}")

        if checked_summary["error"] or (args.strict_exit and checked_summary["unknown"]):
            return 1
        return 0

    if args.provider == "jyblog":
        results: list[QueryResult] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not args.headed)
            page = browser.new_page()
            try:
                for index, domain in enumerate(domains, start=1):
                    print(f"[{index}/{len(domains)}] 查询: {domain}")
                    result = query_jyblog_page(page, domain, args.timeout)
                    results.append(result)
                    print_result(result)

                    if index < len(domains) and args.delay > 0:
                        time.sleep(args.delay)
            finally:
                browser.close()

        write_results(args.output, results)
        summary = summarize(results)
        print("\n查询完成！")
        print_summary(summary, found_label="查到备案")
        print(f"结果已保存到 {args.output}")

        if summary["error"] or (args.strict_exit and summary["unknown"]):
            return 1
        return 0

    session = create_http_session()

    apihz_url = ""
    if args.provider == "apihz":
        apihz_url = discover_apihz_icp_url(
            session=session,
            timeout=args.timeout,
            configured_base_url=args.apihz_base_url,
        )
        print(f"实际查询节点: {apihz_url}\n")

    results: list[QueryResult] = []
    for index, domain in enumerate(domains, start=1):
        print(f"[{index}/{len(domains)}] 查询: {domain}")
        result = query_domain(
            session=session,
            domain=domain,
            provider=args.provider,
            apihz_url=apihz_url,
            timeout=args.timeout,
            retries=max(args.retries, 0),
            api_id=args.apihz_id,
            api_key=args.apihz_key,
        )
        results.append(result)
        print_result(result)

        if index < len(domains) and args.delay > 0:
            time.sleep(args.delay)

    write_results(args.output, results)
    summary = summarize(results)
    print("\n查询完成！")
    print_summary(summary, found_label="查到")
    print(f"结果已保存到 {args.output}")

    if summary["error"] or (args.strict_exit and summary["unknown"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
