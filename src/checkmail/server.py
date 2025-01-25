import asyncio
import itertools
import sys
from datetime import datetime
from typing import Iterable

import aiohttp
import apsw
import regex
from litestar import Litestar, Request, Response, get
from litestar.config.allowed_hosts import AllowedHostsConfig

from . import __version__
from .data import WHITELISTED_EMAILS, compiled_regex_email_pattern

connection = apsw.Connection("domains.db")
cursor = connection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY)")

def check_domain_exists(db_connection, domain):
    cursor = db_connection.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM domains WHERE domain = ?)", (domain,))
    exists = cursor.fetchone()[0]
    return bool(exists)

@get("/version")
def version() -> dict:
    return Response(
        {
            "core": __version__,
            "platform": f"Python {sys.version}",
            "version": __version__,
        }
    )


@get("/healthcheck")
def healthcheck() -> None:
    return Response(content=None, status_code=200)

@get("/", cache=120, sync_to_thread=True)
def index(request: Request, email: str | None = None) -> dict:
    now = datetime.now().astimezone()
    formatted_date = now.strftime("%Y-%m-%d %H:%M:%S %z")
    if not email:
        return Response(
            content={"error": "email is required parameter"}, status_code=422
        )
    if email in WHITELISTED_EMAILS:
        return Response(
            {
                "date": formatted_date,
                "email": email,
                "validation_type": "whitelist",
                "success": True,
                "errors": None,
                "smtp_debug": None,
                "configuration": {
                    "validation_type_by_domain": None,
                    "whitelisted_emails": WHITELISTED_EMAILS,
                    "blacklisted_emails": None,
                    "whitelisted_domains": None,
                    "blacklisted_domains": None,
                    "whitelist_validation": False,
                    "blacklisted_mx_ip_addresses": None,
                    "dns": None,
                    "email_pattern": "default gem value",
                    "not_rfc_mx_lookup_flow": False,
                    "smtp_error_body_pattern": "default gem value",
                    "smtp_fail_fast": False,
                    "smtp_safe_check": False,
                },
            }
        )
    mail_match = regex.fullmatch(compiled_regex_email_pattern, email)
    if not mail_match:
        return Response(content={"error": "invalid email address"}, status_code=422)
    if check_domain_exists(connection, email.split("@")[1]):
            return Response(
                {
                    "date": formatted_date,
                    "email": email,
                    "validation_type": "is_disposable",
                    "success": False,
                    "errors": None,
                    "smtp_debug": None,
                    "configuration": {
                        "validation_type_by_domain": None,
                        "whitelisted_emails": WHITELISTED_EMAILS,
                        "blacklisted_emails": None,
                        "whitelisted_domains": None,
                        "blacklisted_domains": None,
                        "whitelist_validation": False,
                        "blacklisted_mx_ip_addresses": None,
                        "dns": None,
                        "email_pattern": "default gem value",
                        "not_rfc_mx_lookup_flow": False,
                        "smtp_error_body_pattern": "default gem value",
                        "smtp_fail_fast": False,
                        "smtp_safe_check": False,
                    },
                }
            )
    return Response(
        {
            "date": formatted_date,
            "email": email,
            "validation_type": "is_disposable",
            "success": True,
            "errors": None,
            "smtp_debug": None,
            "configuration": {
                "validation_type_by_domain": None,
                "whitelisted_emails": WHITELISTED_EMAILS,
                "blacklisted_emails": None,
                "whitelisted_domains": None,
                "blacklisted_domains": None,
                "whitelist_validation": False,
                "blacklisted_mx_ip_addresses": None,
                "dns": None,
                "email_pattern": "default gem value",
                "not_rfc_mx_lookup_flow": False,
                "smtp_error_body_pattern": "default gem value",
                "smtp_fail_fast": False,
                "smtp_safe_check": False,
            },
        }
    )


async def startup(app: Litestar):
    asyncio.create_task(check_email_domains())


app = Litestar(
    [index, version, healthcheck],
    allowed_hosts=AllowedHostsConfig(allowed_hosts=["cm.amase.cc", "127.0.0.1"]),
    on_startup=[startup],
)


async def extract_domains(text: str):
    domain_pattern = r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}"
    return set(regex.findall(domain_pattern, text))


async def update_domains(db_connection: apsw.Connection, new_domains):
    cursor = db_connection.cursor()
    cursor.execute("SELECT domain FROM domains")
    existing_domains = {row[0] for row in cursor.fetchall()}
    for domain in new_domains:
        cursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?)", (domain,))
    for domain in existing_domains - new_domains:
        cursor.execute("DELETE FROM domains WHERE domain = ?", (domain,))


def remove_empty_keys(iterable: Iterable[str]) -> list:
    return [s for s in iterable if s.strip()]

async def check_email_domains():
    while True:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf"
            ) as resp:
                r1_text: str = await resp.text()
                list1: list[str] = r1_text.split("\n")
            async with session.get(
                "https://raw.githubusercontent.com/chan-mai/kukulu-disposable-email-list/refs/heads/main/domains.txt"
            ) as resp2:
                r2_text: str = await resp2.text()
                list2: list[str] = r2_text.split("\n")
            domains = set(sorted(remove_empty_keys(itertools.chain(list1, list2))))
            await update_domains(connection, domains)
            print("Domain Updated :D")
        await asyncio.sleep(3600)
