import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    VERIFY_SSL,
    DIRBUST_TIMEOUT,
    ADMIN_PANELS,
    ADMIN_SUCCESS_CODES,
)


def find_admin_panels(target: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] Admin Panel Taraması (Dirbusting)...")
    base_urls = [f"http://{target}/", f"https://{target}/"]
    found = False

    for base_url in base_urls:
        try:
            requests.head(base_url, headers=HEADERS, timeout=DIRBUST_TIMEOUT, verify=VERIFY_SSL)
        except requests.exceptions.RequestException:
            continue

        for panel in ADMIN_PANELS:
            url = base_url + panel
            try:
                res = requests.head(
                    url,
                    headers=HEADERS,
                    timeout=DIRBUST_TIMEOUT,
                    verify=VERIFY_SSL,
                    allow_redirects=False,
                )
                if res.status_code in ADMIN_SUCCESS_CODES:
                    if res.status_code in [301, 302] and res.headers.get('Location') == "/":
                        continue
                    print(Fore.RED + Style.BRIGHT + f"    [+] Potansiyel Panel [{res.status_code}] : {url}")
                    found = True
            except requests.exceptions.RequestException:
                pass

    if not found:
        print(Fore.GREEN + "    [-] Açık yönetim paneli tespit edilemedi.")
