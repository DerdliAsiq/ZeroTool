import os

# HTTP headers
HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# SSL
VERIFY_SSL: bool = True

# Timeout değerleri
SOCKET_TIMEOUT: float = 2.0
WHOIS_TIMEOUT: float = 3.0
HTTP_TIMEOUT: float = 5.0
DNS_TIMEOUT: float = 5.0
DIRBUST_TIMEOUT: float = 2.0

# WHOIS
WHOIS_HOST: str = "whois.iana.org"
WHOIS_PORT: int = 43

# Port listesi
SCAN_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 8080]
HTTP_PORTS: list[int] = [80, 443, 8080]

# Web altyapı sızıntı başlıkları
CRITICAL_HEADERS: list[str] = [
    'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator', 'Via'
]

# WAF imzaları
WAF_SERVER_SIGNATURES: dict[str, str] = {
    "cloudflare": "Cloudflare",
    "imperva": "Cloudflare",
    "incapsula": "Imperva",
    "sucuri": "Sucuri",
    "akamai": "Akamai",
}

WAF_HEADER_SIGNATURES: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
}

# WAF cevap kodları
WAF_STATUS_CODES: list[int] = [403, 406, 429]

# SQLi+XSS payload
WAF_PAYLOAD: str = "/?id=1'+OR+'1'='1'%00<script>alert('Vigilante')</script>"

# Admin panel yolları
ADMIN_PANELS: list[str] = [
    "admin", "administrator", "admin1", "admin/login", "wp-login.php", "wp-admin",
    "cpanel", "login", "controlpanel", "dashboard", "manager", "panel", "admin_area",
    "admin.php", "admin.html", "administratorlogin", "backend", "auth", "portal",
    "user/login", "admin/index", "webadmin", "sysadmin", "system",
]

# Admin panel başarılı durum kodları
ADMIN_SUCCESS_CODES: list[int] = [200, 401, 403, 301, 302]

# OSINT
DNS_RECORD_TYPES: dict[str, int] = {'A': 1, 'MX': 15, 'TXT': 16, 'NS': 2}

# Banner
BANNER_FONT: str = "slant"
BANNER_TEXT: str = "ZERO DAY"

OS_NAME: str = os.name
