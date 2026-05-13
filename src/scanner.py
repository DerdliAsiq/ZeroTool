import socket

import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    VERIFY_SSL,
    SOCKET_TIMEOUT,
    HTTP_TIMEOUT,
    SCAN_PORTS,
    HTTP_PORTS,
    CRITICAL_HEADERS,
)


def analyze_web_infrastructure(target: str, port: int) -> None:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{target}:{port}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=VERIFY_SSL)
        headers = response.headers
        print(Fore.CYAN + f"\n    [>] Web Altyapı ({url})")
        leak_detected = False
        for header in CRITICAL_HEADERS:
            if header in headers:
                print(Fore.YELLOW + f"        └─ {header:<16}: " + Fore.RED + headers[header])
                leak_detected = True
        if not leak_detected:
            print(Fore.GREEN + "        └─ Hardening aktif.")
    except requests.exceptions.RequestException:
        print(Fore.MAGENTA + "        └─ [!] Timeout.")


def scan_and_fingerprint(target: str, target_ip: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + "\n[*] Port ve Versiyon Taraması...")
    http_ports: list[int] = []
    for port in SCAN_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((target_ip, port)) == 0:
                print(Fore.GREEN + f"    [+] Port {port:<4} AÇIK")
                if port in HTTP_PORTS:
                    http_ports.append(port)
                else:
                    try:
                        s.settimeout(SOCKET_TIMEOUT)
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            print(Fore.YELLOW + "        └─ Banner : " + Fore.RED + banner.split('\n')[0].strip())
                    except Exception:
                        pass
            s.close()
        except socket.error:
            pass
    if http_ports:
        print(Fore.BLUE + Style.BRIGHT + "\n[*] Web Derin Analizi...")
        for h_port in http_ports:
            analyze_web_infrastructure(target, h_port)
