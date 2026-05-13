import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    VERIFY_SSL,
    HTTP_TIMEOUT,
    WAF_PAYLOAD,
    WAF_SERVER_SIGNATURES,
    WAF_HEADER_SIGNATURES,
    WAF_STATUS_CODES,
)


def detect_waf(target: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] WAF/IPS Tespiti...")
    urls_to_test = [f"http://{target}{WAF_PAYLOAD}", f"https://{target}{WAF_PAYLOAD}"]

    for url in urls_to_test:
        try:
            res = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=VERIFY_SSL)
            headers_lower = {k.lower(): v.lower() for k, v in res.headers.items()}

            waf_detected = False
            waf_name = "Bilinmiyor"

            if 'server' in headers_lower:
                srv = headers_lower['server']
                for signature, name in WAF_SERVER_SIGNATURES.items():
                    if signature in srv:
                        waf_name = name
                        waf_detected = True
                        break

            if not waf_detected:
                for signature, name in WAF_HEADER_SIGNATURES.items():
                    if signature in headers_lower:
                        waf_name = name
                        waf_detected = True
                        break

            if waf_detected:
                print(Fore.RED + Style.BRIGHT + f"    [!] WAF Tespit Edildi ({url.split('://')[0]}): {waf_name}")
                return
            elif res.status_code in WAF_STATUS_CODES:
                print(Fore.YELLOW + f"    [!] İstek {res.status_code} ile reddedildi. WAF veya ModSecurity aktif.")
                return
        except requests.exceptions.RequestException:
            pass

    print(Fore.GREEN + "    [-] Güvenlik Duvarı İmzası Bulunamadı.")
