import os
import subprocess
import sys

from colorama import Fore, Style

from src.config import REPO_BRANCH

update_available: bool = False


def check_updates(auto: bool = False) -> bool:
    try:
        subprocess.run(
            ["git", "fetch", "origin", REPO_BRANCH],
            capture_output=True,
            timeout=10,
        )
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/" + REPO_BRANCH],
            capture_output=True,
            text=True,
            timeout=5,
        )
        behind = int(result.stdout.strip())
        if behind > 0:
            global update_available
            update_available = True
            if auto:
                print(Fore.YELLOW + Style.BRIGHT +
                      f"\n[*] Yeni güncelleme mevcut ({behind} değişiklik). "
                      "Yüklemek için menüde [U] tuşuna basın.")
            return True
    except Exception:
        pass
    return False


def apply_updates() -> None:
    print(Fore.YELLOW + Style.BRIGHT + "\n[*] Güncelleme indiriliyor...")
    try:
        subprocess.run(
            ["git", "pull", "origin", REPO_BRANCH],
            timeout=30,
        )
        print(Fore.GREEN + "[+] Güncelleme tamam. Yeniden başlatılıyor...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(Fore.RED + f"[!] Güncelleme başarısız: {e}")
        input(Fore.CYAN + "\nDevam etmek için [ENTER] tuşuna basın...")
