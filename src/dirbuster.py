import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    VERIFY_SSL,
    DIRBUST_TIMEOUT,
    ADMIN_PANELS,
    ADMIN_SUBDOMAINS,
    ADMIN_SUCCESS_CODES,
)


def _check_url(url: str) -> int | None:
    try:
        res = requests.head(
            url,
            headers=HEADERS,
            timeout=DIRBUST_TIMEOUT,
            verify=VERIFY_SSL,
            allow_redirects=False,
        )
        if res.status_code in ADMIN_SUCCESS_CODES:
            if res.status_code in (301, 302) and res.headers.get('Location') == "/":
                return None
            return res.status_code
    except requests.exceptions.RequestException:
        pass
    return None


def find_admin_panels(target: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] Admin Panel Taraması (Dirbusting)...")

    scheme_list = ["https", "http"] if target.startswith("http") else ["https", "http"]
    base_urls = [f"{s}://{target}/" for s in scheme_list]

    found = False

    # Suffix taraması: site.com/admin
    for base_url in base_urls:
        try:
            requests.head(base_url, headers=HEADERS, timeout=DIRBUST_TIMEOUT, verify=VERIFY_SSL)
        except requests.exceptions.RequestException:
            continue

        for panel in ADMIN_PANELS:
            url = base_url + panel
            status = _check_url(url)
            if status:
                print(Fore.GREEN + Style.BRIGHT + f"    [+] Potansiyel Panel [{status}] : {url}")
                found = True

    # Subdomain (prefix) taraması: admin.site.com
    for prefix in ADMIN_SUBDOMAINS:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{prefix}.{target}/"
            status = _check_url(url)
            if status:
                print(Fore.GREEN + Style.BRIGHT + f"    [+] Potansiyel Panel [{status}] : {url}")
                found = True

            # Kombinasyon: admin.site.com/admin
            for panel in ADMIN_PANELS:
                url2 = f"{scheme}://{prefix}.{target}/{panel}"
                status2 = _check_url(url2)
                if status2:
                    print(Fore.GREEN + Style.BRIGHT + f"    [+] Potansiyel Panel [{status2}] : {url2}")
                    found = True

    if not found:
        print(Fore.RED + "    [-] Açık yönetim paneli tespit edilemedi.")
