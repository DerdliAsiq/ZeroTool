import re
import socket
import ssl as ssl_module

import requests
from colorama import Fore, Style

from src.config import (
    HEADERS,
    VERIFY_SSL,
    WHOIS_TIMEOUT,
    DNS_TIMEOUT,
    SOCKET_TIMEOUT,
    HTTP_TIMEOUT,
    DIRBUST_TIMEOUT,
    WHOIS_HOST,
    WHOIS_PORT,
    DNS_RECORD_TYPES,
    SCAN_PORTS,
    HTTP_PORTS,
    CRITICAL_HEADERS,
    SECURITY_HEADERS,
    COMMON_FILES,
    SOCIAL_MEDIA_DOMAINS,
)


def _section(title: str) -> None:
    print(Fore.CYAN + Style.BRIGHT + f"\n{'=' * 60}")
    print(Fore.WHITE + Style.BRIGHT + f"  {title}")
    print(Fore.CYAN + Style.BRIGHT + f"{'=' * 60}")


def _subsection(title: str) -> None:
    print(Fore.BLUE + Style.BRIGHT + f"\n[*] {title}...")


def _ok(msg: str) -> None:
    print(Fore.GREEN + f"    [+] {msg}")


def _info(msg: str) -> None:
    print(Fore.YELLOW + f"    [i] {msg}")


def _warn(msg: str) -> None:
    print(Fore.MAGENTA + f"    [!] {msg}")


def _fail(msg: str) -> None:
    print(Fore.RED + f"    [-] {msg}")


def _get_homepage(domain: str) -> str | None:
    for scheme in ("https", "http"):
        try:
            res = requests.get(
                f"{scheme}://{domain}", headers=HEADERS,
                timeout=HTTP_TIMEOUT, verify=VERIFY_SSL,
            )
            if res.status_code == 200:
                return res.text
        except requests.exceptions.RequestException:
            pass
    return None


def _gather_whois(domain: str) -> None:
    _subsection("WHOIS Sorgusu")
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

        text = response.decode('utf-8', errors='ignore')

        emails = set(re.findall(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text
        ))
        for email in emails:
            if "abuse" not in email.lower() and "iana" not in email.lower():
                _ok(f"E-Posta: {email}")

        if not emails:
            _fail("E-posta kaydı bulunamadı.")
    except Exception:
        _warn("WHOIS başarısız.")


def _gather_subdomains(domain: str) -> None:
    _subsection("Subdomain Keşfi")
    subdomains: set[str] = set()
    try:
        res = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS, timeout=10,
        )
        if res.status_code == 200:
            for entry in res.json():
                name = entry['name_value'].lower()
                if not name.startswith("*"):
                    subdomains.add(name)
    except Exception:
        pass

    if not subdomains:
        try:
            res = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers=HEADERS, timeout=10,
            )
            if res.status_code == 200 and "error" not in res.text.lower():
                for line in res.text.strip().split('\n'):
                    sub = line.split(',')[0].lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
        except Exception:
            pass

    if subdomains:
        _ok(f"{len(subdomains)} adet alt alan adı bulundu.")
        for sub in sorted(subdomains)[:15]:
            print(Fore.GREEN + f"        └─ {sub}")
        if len(subdomains) > 15:
            _info(f"... ve {len(subdomains) - 15} tane daha.")
    else:
        _fail("Subdomain bulunamadı.")


def _gather_dns(domain: str) -> None:
    _subsection("DNS Kayıtları")
    for rec_name, rec_type in DNS_RECORD_TYPES.items():
        try:
            res = requests.get(
                f"https://dns.google/resolve?name={domain}&type={rec_type}",
                headers=HEADERS, timeout=DNS_TIMEOUT,
            ).json()
            if 'Answer' in res:
                for answer in res['Answer']:
                    data = answer['data']
                    if rec_name == 'TXT' and ('spf' in data.lower() or 'dmarc' in data.lower()):
                        _info(f"{rec_name} (Güvenlik): {data}")
                    else:
                        _ok(f"{rec_name}: {data}")
        except Exception:
            pass


def _gather_ports(target_ip: str) -> set[int]:
    _subsection("Port Taraması")
    http_ports: list[int] = []
    open_ports: list[int] = []
    for port in SCAN_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((target_ip, port)) == 0:
                _ok(f"Port {port} AÇIK")
                open_ports.append(port)
                if port in HTTP_PORTS:
                    http_ports.append(port)
                else:
                    try:
                        s.settimeout(SOCKET_TIMEOUT)
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            _info(f"Banner ({port}): {banner.split(chr(10))[0].strip()}")
                    except Exception:
                        pass
            s.close()
        except socket.error:
            pass

    if not open_ports:
        _fail("Açık port bulunamadı.")

    return set(http_ports)


def _gather_web_infra(target: str, http_ports: set[int]) -> None:
    if not http_ports:
        return
    _subsection("Web Altyapı Analizi")
    for port in http_ports:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{target}:{port}"
        try:
            res = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT, verify=VERIFY_SSL)
            headers = res.headers
            _info(f"Altyapı ({url})")
            for h in CRITICAL_HEADERS:
                if h in headers:
                    _warn(f"{h}: {headers[h]}")
            if not any(h in headers for h in CRITICAL_HEADERS):
                _ok("Hardening aktif (bilgi sızıntısı yok).")
        except requests.exceptions.RequestException:
            _warn(f"{url} bağlantı başarısız.")


def _gather_robots_txt(domain: str) -> None:
    _subsection("robots.txt Analizi")
    for scheme in ("https", "http"):
        try:
            res = requests.get(
                f"{scheme}://{domain}/robots.txt",
                headers=HEADERS, timeout=DIRBUST_TIMEOUT, verify=VERIFY_SSL,
            )
            if res.status_code == 200:
                _ok(f"robots.txt bulundu ({scheme})")
                disallows = re.findall(r"Disallow:\s*(.+)", res.text, re.I)
                allows = re.findall(r"Allow:\s*(.+)", res.text, re.I)
                for d in disallows:
                    _info(f"Disallow: {d.strip()}")
                for a in allows:
                    _info(f"Allow: {a.strip()}")
                return
        except requests.exceptions.RequestException:
            pass
    _fail("robots.txt bulunamadı.")


def _gather_sitemap(domain: str) -> None:
    _subsection("sitemap.xml Analizi")
    for scheme in ("https", "http"):
        try:
            res = requests.get(
                f"{scheme}://{domain}/sitemap.xml",
                headers=HEADERS, timeout=DIRBUST_TIMEOUT, verify=VERIFY_SSL,
            )
            if res.status_code == 200:
                urls = re.findall(r"<loc>(.+?)</loc>", res.text, re.I)
                if urls:
                    _ok(f"sitemap.xml bulundu ({len(urls)} URL)")
                    for u in urls[:10]:
                        print(Fore.GREEN + f"        └─ {u}")
                    if len(urls) > 10:
                        _info(f"... ve {len(urls) - 10} tane daha.")
                else:
                    _ok("sitemap.xml bulundu (içerik çözümlenemedi).")
                return
        except requests.exceptions.RequestException:
            pass
    _fail("sitemap.xml bulunamadı.")


def _gather_security_headers(domain: str) -> None:
    _subsection("Güvenlik Başlıkları")
    for scheme in ("https", "http"):
        try:
            res = requests.get(
                f"{scheme}://{domain}", headers=HEADERS,
                timeout=HTTP_TIMEOUT, verify=VERIFY_SSL,
            )
            found = False
            for h in SECURITY_HEADERS:
                if h in res.headers:
                    _ok(f"{h}: {res.headers[h][:80]}")
                    found = True
            if not found:
                _fail("Hiçbir güvenlik başlığı bulunamadı.")
            return
        except requests.exceptions.RequestException:
            pass


def _gather_tech(domain: str) -> None:
    _subsection("Teknoloji Tespiti")
    for scheme in ("https", "http"):
        try:
            res = requests.get(
                f"{scheme}://{domain}", headers=HEADERS,
                timeout=HTTP_TIMEOUT, verify=VERIFY_SSL,
            )
            headers = res.headers
            if 'Server' in headers:
                _info(f"Sunucu: {headers['Server']}")
            if 'X-Powered-By' in headers:
                _info(f"Altyapı: {headers['X-Powered-By']}")
            if 'Set-Cookie' in headers:
                cookie = headers['Set-Cookie']
                if 'PHPSESSID' in cookie:
                    _ok("PHP tespit edildi")
                if 'JSESSIONID' in cookie or 'JSESSION' in cookie:
                    _ok("Java (JSP) tespit edildi")
                if 'ASPSESSIONID' in cookie or 'ASP.NET' in cookie:
                    _ok("ASP.NET tespit edildi")
            if 'X-Generator' in headers:
                _info(f"Generator: {headers['X-Generator']}")
            return
        except requests.exceptions.RequestException:
            pass


def _gather_social_media(html: str | None) -> None:
    _subsection("Sosyal Medya Bağlantıları")
    if not html:
        _fail("Sayfa içeriği alınamadı.")
        return

    found = False
    for domain in SOCIAL_MEDIA_DOMAINS:
        pattern = re.compile(
            rf'https?://(?:www\.)?{re.escape(domain)}[^\s"\'<>]+', re.I
        )
        matches = pattern.findall(html)
        for m in set(matches):
            _ok(m)
            found = True
    if not found:
        _fail("Sosyal medya bağlantısı bulunamadı.")


def _gather_ssl(domain: str) -> None:
    _subsection("SSL Sertifika Bilgisi")
    try:
        cert = ssl_module.get_server_certificate((domain, 443))
        x509 = ssl_module.PEM_cert_to_DER_cert(cert)  # noqa
        # SSL bağlantısı ile detaylı bilgi
        ctx = ssl_module.create_default_context()
        with socket.create_connection((domain, 443), timeout=SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_info = ssock.getpeercert()
                if cert_info:
                    issuer = dict(cert_info.get('issuer', []))
                    subject = dict(cert_info.get('subject', []))
                    _ok(f"Ortak İsim (CN): {subject.get('commonName', 'N/A')}")
                    _info(f"Veren: {issuer.get('organizationName', 'N/A')}")
                    _info(f"Geçerlilik: {cert_info.get('notBefore', 'N/A')} -> {cert_info.get('notAfter', 'N/A')}")
                    _info(f"SAN: {', '.join(cert_info.get('subjectAltName', [])) if cert_info.get('subjectAltName') else 'N/A'}")
    except Exception as e:
        _warn(f"SSL bilgisi alınamadı: {e}")


def _gather_reverse_dns(target_ip: str) -> None:
    _subsection("Reverse DNS (PTR)")
    try:
        ptr = socket.gethostbyaddr(target_ip)
        _ok(f"PTR Kaydı: {ptr[0]}")
    except (socket.herror, socket.gaierror):
        _fail("PTR kaydı bulunamadı.")


def _gather_geoip(target_ip: str) -> None:
    _subsection("GeoIP Bilgisi")
    try:
        res = requests.get(
            f"http://ip-api.com/json/{target_ip}",
            headers=HEADERS, timeout=5,
        ).json()
        if res.get('status') == 'success':
            _ok(f"Ülke: {res.get('country', 'N/A')} ({res.get('countryCode', 'N/A')})")
            _ok(f"Şehir: {res.get('city', 'N/A')}")
            _ok(f"ISP: {res.get('isp', 'N/A')}")
            _info(f"Organizasyon: {res.get('org', 'N/A')}")
            _info(f"Koordinat: {res.get('lat', 'N/A')}, {res.get('lon', 'N/A')}")
        else:
            _fail("GeoIP sorgusu başarısız.")
    except Exception:
        _warn("GeoIP sorgusu başarısız.")


def _gather_common_files(domain: str) -> None:
    _subsection("Yaygın Dosya Taraması")
    found = False
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        for fname in COMMON_FILES:
            try:
                res = requests.head(
                    f"{base}/{fname}", headers=HEADERS,
                    timeout=DIRBUST_TIMEOUT, verify=VERIFY_SSL,
                )
                if res.status_code == 200:
                    _warn(f"Dosya bulundu ({res.status_code}): /{fname}")
                    found = True
                elif res.status_code == 403:
                    _info(f"Dosya var (erişim engelli): /{fname}")
                    found = True
            except requests.exceptions.RequestException:
                pass
    if not found:
        _fail("Hassas dosya bulunamadı.")


def _gather_emails(html: str | None) -> None:
    _subsection("E-posta Toplama (Sayfa İçi)")
    if not html:
        _fail("Sayfa içeriği alınamadı.")
        return
    emails = set(re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html
    ))
    # Genel email sağlayıcılarını filtrele
    generic_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
    for e in sorted(emails):
        domain_part = e.split('@')[1].lower()
        if domain_part not in generic_domains:
            _ok(e)
    if not emails:
        _fail("E-posta bulunamadı.")


def _gather_wayback(domain: str) -> None:
    _subsection("Wayback Machine")
    try:
        res = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url={domain}&output=text&limit=0",
            headers=HEADERS, timeout=5,
        )
        if res.status_code == 200 and res.text.strip():
            count = len(res.text.strip().split('\n'))
            _ok(f"Arşivlenmiş anlık görüntü sayısı: {count}")
        else:
            _fail("Wayback Machine kaydı bulunamadı.")
    except Exception:
        _warn("Wayback Machine sorgusu başarısız.")


def deep_info_gathering(target: str, target_ip: str) -> None:
    _section("DERİN BİLGİ TOPLAMA (DEEP INFO)")
    _info(f"Hedef: {target} ({target_ip})")
    print(Fore.YELLOW + "-" * 60)

    _gather_whois(target)
    _gather_subdomains(target)
    _gather_dns(target)

    http_ports = _gather_ports(target_ip)
    _gather_web_infra(target, http_ports)

    html = _get_homepage(target)

    _gather_robots_txt(target)
    _gather_sitemap(target)
    _gather_security_headers(target)
    _gather_tech(target)
    _gather_social_media(html)
    _gather_ssl(target)
    _gather_reverse_dns(target_ip)
    _gather_geoip(target_ip)
    _gather_common_files(target)
    _gather_emails(html)
    _gather_wayback(target)

    _section("İŞLEM TAMAMLANDI")
    _ok("Tüm veriler toplandı.")
