import sys
import time

from colorama import Fore, Style

from src.bootstrapper import bootstrapper
from src.utils import print_banner, get_target_info, separator, pause
from src.recon import get_whois, get_subdomains, get_dns_records
from src.scanner import scan_and_fingerprint
from src.waf_detector import detect_waf
from src.dirbuster import find_admin_panels

bootstrapper()

import urllib3  # noqa: E402
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main_menu() -> None:
    while True:
        print_banner()
        print(Fore.WHITE + Style.BRIGHT + "[ Operasyon Seçimi ]\n")
        print(Fore.GREEN + "  [1] Pasif İstihbarat (OSINT)")
        print(Fore.RED + "  [2] Aktif Tarama (Scanner)")
        print(Fore.MAGENTA + "  [3] Agresif Analiz (Tam Kapsam)")
        print(Fore.YELLOW + "  [4] WAF Kalkan Tespiti")
        print(Fore.YELLOW + "  [5] Admin Panel Bulucu")
        print(Fore.CYAN + "  [X] Operasyonu Sonlandır\n")

        choice = input(Fore.CYAN + "Vigilante@ZeroDay:~$ " + Fore.WHITE).strip().upper()

        if choice == 'X':
            sys.exit(0)

        elif choice in ('1', '2', '3', '4', '5'):
            target, target_ip = get_target_info()
            if not target:
                time.sleep(1)
                continue

            print(Fore.CYAN + f"\n[*] Çözümleme: {target} -> {target_ip}\n")
            separator()

            if choice == '1':
                if target == target_ip:
                    print(Fore.RED + "[!] OSINT sadece Domain adresleri içindir.")
                else:
                    get_whois(target)
                    get_subdomains(target)
                    get_dns_records(target)
            elif choice == '2':
                scan_and_fingerprint(target, target_ip)
            elif choice == '3':
                if target != target_ip:
                    get_whois(target)
                    get_subdomains(target)
                    get_dns_records(target)
                scan_and_fingerprint(target, target_ip)
            elif choice == '4':
                detect_waf(target)
            elif choice == '5':
                if target == target_ip:
                    print(Fore.RED + "[!] Tarama için geçerli Domain gereklidir.")
                else:
                    find_admin_panels(target)

            pause()
        else:
            time.sleep(1)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        sys.exit(0)
