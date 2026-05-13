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

# Versiyon & Güncelleme
VERSION: str = "1.0.0"
GITHUB_REPO_URL: str = "https://github.com/DerdliAsiq/ZeroTool.git"
REPO_BRANCH: str = "main"

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

# Güvenlik başlıkları (değerlendirme için)
SECURITY_HEADERS: list[str] = [
    'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
    'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy',
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

# Admin panel yolları (suffix)
ADMIN_PANELS: list[str] = [
    "admin", "administrator", "admin1", "admin/login", "wp-login.php", "wp-admin",
    "cpanel", "login", "controlpanel", "dashboard", "manager", "panel", "admin_area",
    "admin.php", "admin.html", "administratorlogin", "backend", "auth", "portal",
    "user/login", "admin/index", "webadmin", "sysadmin", "system",
]

# Admin panel subdomain'leri (prefix)
ADMIN_SUBDOMAINS: list[str] = [
    "admin", "cpanel", "whm", "webmail", "mail", "cp", "dashboard",
    "portal", "manager", "adminpanel", "administrator", "admin1",
    "webadmin", "sysadmin", "controlpanel", "panel", "auth", "backend",
]

# Admin panel başarılı durum kodları
ADMIN_SUCCESS_CODES: list[int] = [200, 401, 403, 301, 302]

# OSINT
DNS_RECORD_TYPES: dict[str, int] = {'A': 1, 'MX': 15, 'TXT': 16, 'NS': 2}

# Yaygın hassas dosyalar
COMMON_FILES: list[str] = [
    "robots.txt", "sitemap.xml", ".htaccess", ".env", "config.json",
    "config.php", "db.sql", "backup.sql", "wp-config.php",
    "crossdomain.xml", "phpinfo.php", "info.php", "test.php",
    "error.log", "access.log",
]

# Sosyal medya domain'leri
SOCIAL_MEDIA_DOMAINS: list[str] = [
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "youtube.com", "tiktok.com", "github.com",
    "discord.com", "telegram.org", "whatsapp.com",
]

# Banner
BANNER_FONT: str = "slant"
BANNER_TEXT: str = "ZERO DAY"

OS_NAME: str = os.name
