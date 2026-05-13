import os
import subprocess
import sys
import venv


def bootstrapper() -> None:
    if sys.prefix != sys.base_prefix:
        return

    venv_dir = os.path.join(os.getcwd(), ".venv")

    if os.name == 'nt':
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        venv_python = os.path.join(venv_dir, "bin", "python")

    if not os.path.exists(venv_python):
        print("\n[*] İzole ortam (venv) oluşturuluyor... (Zero-Touch Ops)")
        try:
            venv.create(venv_dir, with_pip=True)
            print("[*] Sanal ortam aktif. Gerekli kütüphaneler kuruluyor...")
            deps = ["pyfiglet", "colorama", "requests", "urllib3"]
            subprocess.check_call(
                [venv_python, "-m", "pip", "install"] + deps,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("[+] Çekirdek kurulum tamamlandı. Sistem yeniden başlatılıyor...\n")
        except Exception as e:
            print(f"\n[!] Kurulum Hatası: {e}")
            print("Termux/iSH üzerinde 'python3-venv' veya tam Python paketinin kurulu olduğundan emin olun.")
            sys.exit(1)

    os.execv(venv_python, [venv_python] + sys.argv)


def post_bootstrap() -> None:
    from src.updater import check_updates
    check_updates(auto=True)
