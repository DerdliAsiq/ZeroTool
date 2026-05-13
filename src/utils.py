import os
import socket
import time

import pyfiglet
from colorama import Fore, Style, init

from src.config import OS_NAME, BANNER_FONT, BANNER_TEXT

init(autoreset=True)


def clear_screen() -> None:
    os.system('clear' if OS_NAME == 'posix' else 'cls')


def print_banner() -> None:
    clear_screen()
    banner = pyfiglet.figlet_format(BANNER_TEXT, font=BANNER_FONT)
    print(Fore.RED + Style.BRIGHT + banner)
    print(Fore.CYAN + " " * 8 + "Advanced Recon & OSINT Framework | Coded by Vigilante\n")
    print(Fore.YELLOW + "-" * 65 + "\n")


def get_target_info() -> tuple[str | None, str | None]:
    raw_target = input(Fore.YELLOW + "\nHedef Domain (Örn: tesla.com) veya IP: " + Fore.WHITE).strip()
    if not raw_target:
        return None, None
    target = raw_target.replace("http://", "").replace("https://", "").split("/")[0]
    try:
        target_ip = socket.gethostbyname(target)
        return target, target_ip
    except socket.gaierror:
        print(Fore.RED + "\n[!] Hata: Domain çözümlenemedi. Adresi kontrol edin.")
        return None, None


def separator() -> None:
    print(Fore.YELLOW + "-" * 65)


def print_info(target: str, target_ip: str) -> None:
    print(Fore.CYAN + f"\n[*] Çözümleme: {target} -> {target_ip}\n")
    separator()


def pause() -> None:
    print(Fore.YELLOW + "\n" + "-" * 65)
    input(Fore.CYAN + "\nDevam etmek için [ENTER] tuşuna basın...")


def domain_required(target: str, target_ip: str) -> bool:
    if target == target_ip:
        print(Fore.RED + "[!] Bu işlem sadece Domain adresleri içindir.")
        time.sleep(1)
        return False
    return True
