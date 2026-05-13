import re
import socket

import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    WHOIS_HOST,
    WHOIS_PORT,
    WHOIS_TIMEOUT,
    DNS_TIMEOUT,
    DNS_RECORD_TYPES,
)


def get_whois(domain: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] WHOIS Analizi...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(WHOIS_TIMEOUT)
        s.connect((WHOIS_HOST, WHOIS_PORT))
        s.send((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()

        emails = set(
            re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                response.decode('utf-8', errors='ignore'),
            )
        )
        if emails:
            for email in emails:
                if "abuse" not in email.lower() and "iana" not in email.lower():
                    print(Fore.YELLOW + "    [+] E-Posta: " + Fore.RED + email)
        else:
            print(Fore.GREEN + "    [-] WHOIS e-posta kaydı bulunamadı.")
    except Exception:
        print(Fore.MAGENTA + "    [!] WHOIS başarısız.")


def get_subdomains(domain: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] Subdomain Keşfi...")
    subdomains: set[str] = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            for entry in res.json():
                name = entry['name_value'].lower()
                if not name.startswith("*"):
                    subdomains.add(name)
    except Exception:
        pass

    if not subdomains:
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            res = requests.get(url, headers=HEADERS, timeout=10)
            if res.status_code == 200 and "error" not in res.text.lower():
                lines = res.text.strip().split('\n')
                for line in lines:
                    sub = line.split(',')[0].lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
        except Exception:
            pass

    if subdomains:
        print(Fore.YELLOW + f"    [+] {len(subdomains)} adet alt alan adı bulundu.")
        for sub in list(subdomains)[:10]:
            print(Fore.GREEN + f"        └─ {sub}")
        if len(subdomains) > 10:
            print(Fore.CYAN + f"        └─ ... ve {len(subdomains) - 10} tane daha.")
    else:
        print(Fore.MAGENTA + "    [-] Subdomain bulunamadı.")


def get_dns_records(domain: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] DNS Analizi...")
    for rec_name, rec_type in DNS_RECORD_TYPES.items():
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rec_type}"
            response = requests.get(url, headers=HEADERS, timeout=DNS_TIMEOUT).json()
            if 'Answer' in response:
                for answer in response['Answer']:
                    data = answer['data']
                    if rec_name == 'TXT' and ('spf' in data.lower() or 'dmarc' in data.lower()):
                        print(Fore.YELLOW + f"    [+] {rec_name} (Güvenlik) : " + Fore.CYAN + data)
                    else:
                        print(Fore.GREEN + f"    [+] {rec_name} Kaydı   : {data}")
        except Exception:
            pass
