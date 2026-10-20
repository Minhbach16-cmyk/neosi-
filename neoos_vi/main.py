#!/usr/bin/env python3
# Code in English, output displayed in Vietnamese
#
# Requirements: pip install requests phonenumbers
# Optional: the `whois` command-line tool (a built-in socket fallback is used otherwise)
# Optional for EXIF: pip install pillow
# Optional for email breach: pip install holehe

import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone as dt_timezone
from email.parser import HeaderParser
from urllib.parse import urlparse

import phonenumbers
import requests
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as pn_timezone

try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---------------------------------------------------------------- mã màu ANSI cho terminal
BL = '\033[30m'    # Đen
R = '\033[1;31m'  # Đỏ đậm
G = '\033[1;32m'  # Xanh lá đậm
Y = '\033[1;33m'  # Vàng đậm
BLU = '\033[1;34m' # Xanh dương đậm
L = '\033[1;35m'# Hồng/Tím đậm
C = '\033[1;36m'  # Xanh lơ đậm
W = '\033[1;37m'  # Trắng đậm
RS = '\033[0m'     # Reset

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0"}
DEFAULT_REGION = "VN"
NA = "Không có"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9\-]+\.)+[A-Za-z0-9\-]{2,63}$")

DNS_TYPES = {
    "A": 1, "AAAA": 28, "CNAME": 5, "MX": 15,
    "NS": 2, "TXT": 16, "SOA": 6, "CAA": 257,
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

PHONE_TYPES = {
    phonenumbers.PhoneNumberType.MOBILE: "Di động",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Cố định",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Cố định hoặc di động",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Miễn phí cước",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Giá cao",
    phonenumbers.PhoneNumberType.SHARED_COST: "Chia sẻ cước",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Số cá nhân",
    phonenumbers.PhoneNumberType.PAGER: "Máy nhắn tin",
    phonenumbers.PhoneNumberType.UAN: "Số truy cập chung",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Hộp thư thoại",
    phonenumbers.PhoneNumberType.UNKNOWN: "Không xác định",
}

SOCIAL_MEDIA = [
    {"url": "https://www.facebook.com/{}", "name": "Facebook"},
    {"url": "https://www.twitter.com/{}", "name": "Twitter/X"},
    {"url": "https://www.instagram.com/{}", "name": "Instagram"},
    {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
    {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
    {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
    {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
    {"url": "https://www.reddit.com/user/{}", "name": "Reddit"},
    {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
    {"url": "https://www.vk.com/{}", "name": "VK"},
    {"url": "https://www.weibo.com/{}", "name": "Weibo"},
    {"url": "https://www.douyin.com/user/{}", "name": "Douyin"},
    {"url": "https://www.mastodon.social/@{}", "name": "Mastodon"},
    {"url": "https://www.threads.net/@{}", "name": "Threads"},
    {"url": "https://www.bluesky.app/profile/{}", "name": "Bluesky"},
    {"url": "https://www.clubhouse.com/@{}", "name": "Clubhouse"},
    {"url": "https://www.mewe.com/i/{}", "name": "MeWe"},
    {"url": "https://www.parler.com/profile/{}", "name": "Parler"},
    {"url": "https://www.gab.com/{}", "name": "Gab"},
    {"url": "https://www.minds.com/{}", "name": "Minds"},
    {"url": "https://www.ok.ru/{}", "name": "OK.ru"},
    {"url": "https://www.line.me/{}", "name": "LINE"},
    {"url": "https://www.kakao.com/{}", "name": "KakaoTalk"},
    {"url": "https://www.youtube.com/@{}", "name": "YouTube"},
    {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
    {"url": "https://www.vimeo.com/{}", "name": "Vimeo"},
    {"url": "https://www.dailymotion.com/{}", "name": "Dailymotion"},
    {"url": "https://www.rumble.com/user/{}", "name": "Rumble"},
    {"url": "https://www.odysee.com/@{}", "name": "Odysee"},
    {"url": "https://www.bitchute.com/channel/{}", "name": "BitChute"},
    {"url": "https://www.bilibili.com/{}", "name": "Bilibili"},
    {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
    {"url": "https://www.spotify.com/user/{}", "name": "Spotify"},
    {"url": "https://www.mixcloud.com/{}", "name": "Mixcloud"},
    {"url": "https://www.audiomack.com/{}", "name": "Audiomack"},
    {"url": "https://www.bandcamp.com/{}", "name": "Bandcamp"},
    {"url": "https://www.last.fm/user/{}", "name": "Last.fm"},
    {"url": "https://www.github.com/{}", "name": "GitHub"},
    {"url": "https://www.gitlab.com/{}", "name": "GitLab"},
    {"url": "https://www.bitbucket.org/{}", "name": "Bitbucket"},
    {"url": "https://www.keybase.io/{}", "name": "Keybase"},
    {"url": "https://www.stackoverflow.com/users/{}", "name": "StackOverflow"},
    {"url": "https://www.dev.to/{}", "name": "Dev.to"},
    {"url": "https://www.hackerrank.com/{}", "name": "HackerRank"},
    {"url": "https://www.hackernews.com/user/{}", "name": "HackerNews"},
    {"url": "https://www.codepen.io/{}", "name": "CodePen"},
    {"url": "https://www.replit.com/@{}", "name": "Replit"},
    {"url": "https://www.kaggle.com/{}", "name": "Kaggle"},
    {"url": "https://www.npmjs.com/~{}", "name": "npm"},
    {"url": "https://www.pypi.org/user/{}", "name": "PyPI"},
    {"url": "https://www.docker.com/u/{}", "name": "Docker Hub"},
    {"url": "https://www.patreon.com/{}", "name": "Patreon"},
    {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
    {"url": "https://www.behance.net/{}", "name": "Behance"},
    {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
    {"url": "https://www.figma.com/@{}", "name": "Figma"},
    {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
    {"url": "https://www.500px.com/{}", "name": "500px"},
    {"url": "https://www.deviantart.com/{}", "name": "DeviantArt"},
    {"url": "https://www.artstation.com/{}", "name": "ArtStation"},
    {"url": "https://www.unsplash.com/@{}", "name": "Unsplash"},
    {"url": "https://www.pixiv.net/users/{}", "name": "Pixiv"},
    {"url": "https://www.ello.co/{}", "name": "Ello"},
    {"url": "https://www.vsco.co/{}", "name": "VSCO"},
    {"url": "https://www.youpic.com/{}", "name": "YouPic"},
    {"url": "https://www.medium.com/@{}", "name": "Medium"},
    {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
    {"url": "https://www.substack.com/@{}", "name": "Substack"},
    {"url": "https://www.wordpress.com/{}", "name": "WordPress"},
    {"url": "https://www.blogger.com/profile/{}", "name": "Blogger"},
    {"url": "https://www.wattpad.com/user/{}", "name": "Wattpad"},
    {"url": "https://www.goodreads.com/{}", "name": "Goodreads"},
    {"url": "https://www.letterboxd.com/{}", "name": "Letterboxd"},
    {"url": "https://www.trakt.tv/users/{}", "name": "Trakt"},
    {"url": "https://www.etsy.com/shop/{}", "name": "Etsy"},
    {"url": "https://www.ebay.com/usr/{}", "name": "eBay"},
    {"url": "https://www.amazon.com/gp/profile/{}", "name": "Amazon"},
    {"url": "https://www.shopify.com/{}", "name": "Shopify"},
    {"url": "https://www.discord.com/users/{}", "name": "Discord"},
    {"url": "https://www.telegram.me/{}", "name": "Telegram"},
    {"url": "https://www.weheartit.com/{}", "name": "We Heart It"},
    {"url": "https://www.9gag.com/u/{}", "name": "9GAG"},
    {"url": "https://www.imgur.com/user/{}", "name": "Imgur"},
    {"url": "https://www.ko-fi.com/{}", "name": "Ko-fi"},
    {"url": "https://www.buymeacoffee.com/{}", "name": "Buy Me a Coffee"},
    {"url": "https://www.strava.com/athletes/{}", "name": "Strava"},
    {"url": "https://www.chess.com/member/{}", "name": "Chess.com"},
    {"url": "https://www.duolingo.com/profile/{}", "name": "Duolingo"},
    {"url": "https://www.trello.com/u/{}", "name": "Trello"},
    {"url": "https://www.notion.so/{}", "name": "Notion"},
    {"url": "https://www.slideshare.net/{}", "name": "SlideShare"},
    {"url": "https://www.scribd.com/{}", "name": "Scribd"},
    {"url": "https://www.academia.edu/{}", "name": "Academia.edu"},
    {"url": "https://www.researchgate.net/profile/{}", "name": "ResearchGate"},
    {"url": "https://www.orcid.org/{}", "name": "ORCID"},
]


# ---------------------------------------------------------------- UI helpers
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def run_banner():
    clear_screen()
    print(f" {W}                             .            {RS}     -- __     __     _       _      ")
    print(f" {W}                            =@@+       {RS}        -- \\ \\   / /   _| |_ __ (_)_  __")
    print(f" {W}                           +@@@@+         {RS}     --  \\ \\ / / | | | | '_ \\| \\ \\/ /")
    print(f" {W}                         .+@@@@@@+.       {RS}     --   \\ V /| |_| | | | | | |>  < ")
    print(f" {W}                        .+@@@@@@@@+.    {RS}       --    \\_/  \\__,_|_|_| |_|_/_/\\_/")
    print(f" {W}                       .+@@@@::@@@@*.     {RS}     --")
    print(f" {W}                       *@@@%:  :%@@@*.        {RS} --  {BLU}By: {C}Nex{RS}")
    print(f" {W}                      #@@@%:    :%@@@#      {RS}   --  {BLU}Version: {C}1.0")
    print(f" {W}                     %@@@%:      :%@@@%    {RS}    --  {BLU}BLUTele: {C}@Nex12z")
    print(f" {W}                   .#@@@%:   ==   :%@@@%. {RS}     ")
    print(f" {W}                  :#@@@%:   +@@+   :%@@@#:                {RS}   ")
    print(f" {W}                 :#@@@%.  .+@@@@*.  .%@@@%:             {RS}     ")
    print(f" {W}                :%@@@#   .+@@@@@@*.   #@@@%:               {RS}  ")
    print(f" {W}               :%@@@*.  .+@@@@@@@@*.  .*@@@%:           {RS}     ")
    print(f" {W}              :@@@@*.  .*@@@%::%@@@*.  .+@@@@:        {RS}       ")
    print(f" {W}             :@@@@*.   *@@@%:  .::::.   .+@@@@:       {RS}       ")
    print(f" {W}            -@@@@+.   #@@@#:             .+@@@@=    {RS}     ")
    print(f" {W}           =%@@@+   .#@@@#:    :%%%%%%%%%%%@@@@@=        {RS}    ")
    print(f" {W}          =@@@@=   :#@@@%:     :@@@@@@@@@@@@@@@@@=   {RS}        ")
    print(f" {W}         =@@@@-   :#@@@#.      .::::::::::::::::::.       {RS}   ")
    print(f" {W}        =@@@@-   :%@@@#.                                  {RS}   ")
    print(f" {W}       =@@@@-   :%@@@*                -%%%#:   :####=    {RS}    ")
    print(f" {W}      *@@@@=   :@@@@%*******:  :*******%@@@@:   =@@@@+     {RS}  ")
    print(f" {W}     *@@@%=    @@@@@@@@@@@@@-  :@@@@@@@@@@@@@.   -%@@@*   {RS}   ")
    print(f" {W}   .*@@@%-   .@@@@@@@@@@@@@@-  :@@@@@@@@@@@@@@.   -%@@@*.  {RS}  ")
    print(f" {W}  .*@@@@:              .%@@@-  :@@@%:              :%@@@*.   ")
    print(f" {W} .+@@@@:...............:%@@@-  :@@@%:...............:@@@@*.  ")
    print(f" {W} .+@@@@@@@@@@@@@@@@@@@@@@@@@-  :@@@@@@@@@@@@@@@@@@@@@@@@@*. {RS} ")
    print(f" {W}  .+%@@@@@@@@@@@@@@@@@@@@@@@:  :@@@@@@@@@@@@@@@@@@@@@@@%*.  {RS} ")
    print(f" {BLU}     ......................    ......................       {RS}")
    print("")

def is_option(func):
    def wrapper(*args, **kwargs):
        run_banner()
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            print(f"\n {Y}[!] Đã hủy thao tác.{RS}")
        input(f"\n {W}Nhấn Enter để quay lại menu...{RS}")
    return wrapper


def field(label, value, color=None):
    print(f" {W}{label:<17}:{color or G} {value}{RS}")


def section(title):
    print(f"\n {W}========== {G}{title} {W}=========={RS}")


def ask_save(report, name):
    answer = input(f"\n {W}Lưu kết quả ra file JSON? (y/N): {G}").strip().lower()
    if answer != "y":
        return
    safe = re.sub(r"[^\w.-]", "_", name)
    filename = f"report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=str)
        print(f" {G}Đã lưu: {W}{os.path.abspath(filename)}{RS}")
    except OSError as e:
        print(f" {R}Lỗi: Không ghi được file: {e}{RS}")


# ---------------------------------------------------------------- input helpers
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def to_ascii_domain(host):
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def is_valid_domain(host):
    return bool(DOMAIN_RE.match(host))


def normalize_target(raw):
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    else:
        raw = raw.split("/")[0]
        if raw.count(":") == 1:
            raw = raw.split(":")[0]
    raw = raw.strip().strip(".")
    return raw if is_ip(raw) else to_ascii_domain(raw)


def registrable_domain(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in {"co", "com", "net", "org", "gov", "edu", "ac"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def ask_domain():
    host = normalize_target(input(f"{W}\n Nhập tên miền (vd: example.com) : {G}"))
    if is_ip(host) or not is_valid_domain(host):
        print(f"\n{R} Lỗi: Cần nhập một tên miền hợp lệ.{RS}")
        return None
    return host


def read_multiline(prompt):
    print(prompt)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------- WHOIS
def whois_socket(server, query):
    try:
        s = socket.create_connection((server, 43), timeout=10)
        s.sendall((query + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return data.decode("utf-8", errors="ignore")
    except (socket.timeout, socket.error, OSError):
        return None


def whois_domain(domain):
    if not is_valid_domain(domain):
        return None
    try:
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=25)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    raw = whois_socket("whois.verisign-grs.com", "=" + domain)
    if raw:
        m = re.search(r"Registrar WHOIS Server:[ \t]*(\S+)", raw)
        if m:
            raw2 = whois_socket(m.group(1).strip(), domain)
            if raw2:
                raw = raw + "\n" + raw2
        return raw
    raw_iana = whois_socket("whois.iana.org", domain)
    if raw_iana:
        m = re.search(r"whois:[ \t]*(\S+)", raw_iana)
        if m:
            raw2 = whois_socket(m.group(1).strip(), domain)
            if raw2:
                return raw2
    return None


def parse_date(text):
    if not text:
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=dt_timezone.utc)
    except ValueError:
        return None


def parse_whois(raw, domain):
    result = {
        "domain": domain, "creation_date": None, "expiry_date": None,
        "updated_date": None, "age_days": None, "days_left": None,
        "registrar": None, "registrar_url": None, "iana_id": None,
        "registrant": None, "org": None, "street": None, "city": None,
        "state": None, "postal": None, "country": None,
        "emails": [], "phones": [], "name_servers": [], "statuses": [],
        "dnssec": None, "error": None,
    }
    if not raw:
        result["error"] = "Không lấy được dữ liệu whois"
        return result

    def get(pattern):
        m = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    result["creation_date"] = get(r"^\s*Creation Date:[ \t]*(.+)$")
    result["updated_date"] = get(r"^\s*Updated Date:[ \t]*(.+)$")
    result["expiry_date"] = (
        get(r"^\s*Registry Expiry Date:[ \t]*(.+)$")
        or get(r"^\s*Registrar Registration Expiration Date:[ \t]*(.+)$")
        or get(r"^\s*Expiration Date:[ \t]*(.+)$")
    )
    result["registrar"] = get(r"^\s*Registrar:[ \t]*(.+)$")
    result["registrar_url"] = get(r"^\s*Registrar URL:[ \t]*(.+)$")
    result["iana_id"] = get(r"^\s*Registrar IANA ID:[ \t]*(.+)$")
    result["registrant"] = (get(r"^\s*Registrant Name:[ \t]*(.+)$")
                            or get(r"^\s*Registrant Organization:[ \t]*(.+)$"))
    result["org"] = get(r"^\s*Registrant Organization:[ \t]*(.+)$")
    result["street"] = get(r"^\s*Registrant Street:[ \t]*(.+)$")
    result["city"] = get(r"^\s*Registrant City:[ \t]*(.+)$")
    result["state"] = get(r"^\s*Registrant State/Province:[ \t]*(.+)$")
    result["postal"] = get(r"^\s*Registrant Postal Code:[ \t]*(.+)$")
    result["country"] = get(r"^\s*Registrant Country:[ \t]*(.+)$")

    now = datetime.now(dt_timezone.utc)
    created = parse_date(result["creation_date"])
    expires = parse_date(result["expiry_date"])
    if created:
        result["age_days"] = (now - created).days
    if expires:
        result["days_left"] = (expires - now).days

    for name in ("Registrant Email", "Admin Email", "Tech Email", "Billing Email",
                 "Registrar Abuse Contact Email"):
        val = get(rf"^\s*{name}:[ \t]*(.+)$")
        if val and "@" in val:
            for e in re.split(r"[,;\s]+", val):
                if "@" in e and e not in result["emails"]:
                    result["emails"].append(e)
    for name in ("Registrant Phone", "Admin Phone", "Tech Phone", "Billing Phone",
                 "Registrant Fax", "Admin Fax", "Tech Fax", "Billing Fax",
                 "Registrar Abuse Contact Phone"):
        val = get(rf"^\s*{name}:[ \t]*(.+)$")
        if val:
            val = val.strip().rstrip(".")
            if val and val not in result["phones"]:
                result["phones"].append(val)
    for m in re.finditer(r"^\s*Name Server:[ \t]*(.+)$", raw, re.IGNORECASE | re.MULTILINE):
        ns = m.group(1).strip().lower()
        if ns and ns not in result["name_servers"]:
            result["name_servers"].append(ns)
    for m in re.finditer(r"^\s*Domain Status:[ \t]*(\S+)", raw, re.IGNORECASE | re.MULTILINE):
        st = m.group(1).strip()
        if st and st not in result["statuses"]:
            result["statuses"].append(st)
    result["dnssec"] = get(r"^\s*DNSSEC:[ \t]*(.+)$")
    return result


def print_whois(w):
    section("THÔNG TIN WHOIS TÊN MIỀN")
    field("Tên miền", w["domain"])
    if w["error"]:
        field("Lỗi", w["error"], R)
        return
    field("Ngày đăng ký", w["creation_date"] or NA)
    if w["age_days"] is not None:
        field("Tuổi tên miền", f"{w['age_days']} ngày (~{w['age_days'] / 365.25:.1f} năm)")
    field("Ngày hết hạn", w["expiry_date"] or NA)
    if w["days_left"] is not None:
        color = R if w["days_left"] < 30 else G
        field("Còn lại", f"{w['days_left']} ngày", color)
    field("Ngày cập nhật", w["updated_date"] or NA)
    field("Nhà đăng ký", w["registrar"] or NA)
    field("URL nhà đăng ký", w["registrar_url"] or NA)
    field("IANA ID", w["iana_id"] or NA)
    for key, label in (("registrant", "Chủ sở hữu"), ("org", "Tổ chức"),
                       ("street", "Địa chỉ"), ("city", "Thành phố"),
                       ("state", "Tỉnh/Bang"), ("postal", "Mã bưu chính"),
                       ("country", "Quốc gia")):
        if w[key]:
            field(label, w[key])
    field("Email", ", ".join(w["emails"][:8]) if w["emails"] else "Không có trong whois",
          None if w["emails"] else Y)
    field("Số điện thoại", ", ".join(w["phones"][:8]) if w["phones"] else "Không có trong whois",
          None if w["phones"] else Y)
    if w["name_servers"]:
        field("Name Server", ", ".join(w["name_servers"]))
    if w["statuses"]:
        field("Trạng thái", ", ".join(w["statuses"]))
    if w["dnssec"]:
        field("DNSSEC", w["dnssec"])


# ---------------------------------------------------------------- DNS (system resolver)
def reverse_dns(ip):
    result = {"ip": ip, "hostname": None, "aliases": [], "forward_confirmed": False,
              "forward_ips": [], "error": None}
    try:
        hostname, aliases, addr_list = socket.gethostbyaddr(ip)
        result["hostname"] = hostname
        result["aliases"] = aliases
        result["forward_ips"] = addr_list
        try:
            _, _, fwd_ips = socket.gethostbyname_ex(hostname)
            if ip in fwd_ips:
                result["forward_confirmed"] = True
        except socket.gaierror:
            pass
    except socket.herror as e:
        result["error"] = f"Không có bản ghi PTR ({e})"
    except socket.gaierror as e:
        result["error"] = f"Lỗi phân giải ({e})"
    return result


def print_reverse_dns(rev):
    section("PHÂN GIẢI NGƯỢC DNS (PTR)")
    field("Địa chỉ IP", rev["ip"])
    if rev["hostname"]:
        field("Tên miền (PTR)", rev["hostname"])
        if rev["aliases"]:
            field("Bí danh", ", ".join(rev["aliases"]))
        if rev["forward_ips"]:
            field("IP forward", ", ".join(rev["forward_ips"]))
        if rev["forward_confirmed"]:
            field("Trạng thái FCrDNS", "OK (forward-confirmed)")
        else:
            field("Trạng thái FCrDNS", "Không khớp forward", Y)
    else:
        field("Tên miền (PTR)", rev["error"] or NA, R)


def guess_domain_from_ptr(rev):
    if not rev["hostname"]:
        return []
    parts = rev["hostname"].rstrip(".").split(".")
    guesses = [".".join(parts[-n:]) for n in (2, 3) if len(parts) >= n]
    return list(dict.fromkeys(guesses))


def resolve_target(target):
    result = {"input": target, "is_ip": False, "ipv4": [], "ipv6": [],
              "canonical": None, "aliases": []}
    if is_ip(target):
        result["is_ip"] = True
        result["canonical"] = target
        (result["ipv6"] if ":" in target else result["ipv4"]).append(target)
        return result
    try:
        hostname, aliases, ipv4_list = socket.gethostbyname_ex(target)
        result["canonical"] = hostname
        result["aliases"] = aliases
        result["ipv4"] = ipv4_list
    except (socket.gaierror, UnicodeError):
        pass
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET6)
        result["ipv6"] = list(dict.fromkeys(info[4][0] for info in infos))
    except (socket.gaierror, UnicodeError):
        pass
    return result


def print_resolution(res):
    section("PHÂN GIẢI TÊN MIỀN")
    field("Đầu vào", res["input"])
    field("Là IP", res["is_ip"])
    if res["canonical"]:
        field("Tên chuẩn", res["canonical"])
    if res["aliases"]:
        field("Bí danh (CNAME)", ", ".join(res["aliases"]))
    if res["ipv4"]:
        field("Địa chỉ IPv4", ", ".join(res["ipv4"]))
    else:
        field("Địa chỉ IPv4", "Không tìm thấy", R)
    if res["ipv6"]:
        field("Địa chỉ IPv6", ", ".join(res["ipv6"]))
    else:
        field("Địa chỉ IPv6", "Không có bản ghi AAAA", Y)


# ---------------------------------------------------------------- IP -> domain / contacts / geolocation
def find_domain_from_ip(ip, rev=None):
    found = {"ptr": None, "ipwho_domain": None, "ipapi_org": None,
             "rdap_name": None, "suggestions": []}
    rev = rev or reverse_dns(ip)
    if rev["hostname"]:
        found["ptr"] = rev["hostname"].rstrip(".")
        found["suggestions"].extend(guess_domain_from_ptr(rev))
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=8, headers=HEADERS).json()
        if r.get("success") and isinstance(r.get("connection"), dict):
            d = r["connection"].get("domain")
            if d:
                found["ipwho_domain"] = d
                found["suggestions"].append(d)
    except (requests.RequestException, ValueError):
        pass
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8, headers=HEADERS).json()
        found["ipapi_org"] = r.get("org") or r.get("asn")
    except (requests.RequestException, ValueError):
        pass
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=8, headers=HEADERS).json()
        found["rdap_name"] = r.get("name") or r.get("handle")
    except (requests.RequestException, ValueError):
        pass
    found["suggestions"] = list(dict.fromkeys(g for g in found["suggestions"] if g))
    return found


def contacts_from_ip(ip):
    found = {"emails": [], "phones": [], "orgs": [], "network_name": None,
             "country": None, "error": None}
    urls = [
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
    ]
    data = None
    for url in urls:
        try:
            r = requests.get(url, timeout=TIMEOUT,
                             headers={**HEADERS, "Accept": "application/rdap+json"})
            if r.status_code == 200:
                data = r.json()
                break
        except (requests.RequestException, ValueError):
            continue
    if not data:
        found["error"] = "Không truy vấn được RDAP IP"
        return found

    found["network_name"] = data.get("name")
    found["country"] = data.get("country")

    def scan_entity(ent):
        vcard = ent.get("vcardArray") or [None, []]
        fields = vcard[1] if len(vcard) > 1 else []
        for f in fields:
            if len(f) < 4:
                continue
            kind, value = f[0], f[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            if isinstance(value, dict):
                value = value.get("value", "")
            if not value:
                continue
            if kind == "email" and value not in found["emails"]:
                found["emails"].append(value)
            elif kind == "tel":
                value = str(value).replace("tel:", "")
                if value not in found["phones"]:
                    found["phones"].append(value)
            elif kind == "org" and value not in found["orgs"]:
                found["orgs"].append(value)
        for child in ent.get("entities", []):
            scan_entity(child)

    for ent in data.get("entities", []):
        scan_entity(ent)
    return found


def ip_geolocation(ip):
    try:
        data = requests.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT, headers=HEADERS).json()
    except (requests.RequestException, ValueError) as e:
        return {"ip": ip, "error": f"Không kết nối được API: {e}"}
    if not data.get("success", False):
        return {"ip": ip, "error": f"API trả về lỗi cho {ip}: {data.get('message', 'Unknown error')}"}
    data["error"] = None
    return data


def print_geolocation(d):
    print(f"\n {W}---------- {G}TRUY VẾT IP: {d['ip']} {W}----------")
    if d.get("error"):
        print(f"{R} Lỗi: {d['error']}{RS}")
        return
    for key, label in (("type", "Loại IP"), ("country", "Quốc gia"),
                       ("country_code", "Mã quốc gia"), ("city", "Thành phố"),
                       ("continent", "Châu lục"), ("continent_code", "Mã châu lục"),
                       ("region", "Vùng"), ("region_code", "Mã vùng"),
                       ("latitude", "Vĩ độ"), ("longitude", "Kinh độ")):
        field(label, d.get(key, "N/A"))

    lat, lon = d.get("latitude"), d.get("longitude")
    if lat is not None and lon is not None:
        field("Bản đồ", f"https://www.google.com/maps?q={lat},{lon}")
    else:
        field("Bản đồ", "N/A")

    for key, label in (("is_eu", "EU"), ("postal", "Mã bưu chính"),
                       ("calling_code", "Mã gọi điện"), ("capital", "Thủ đô"),
                       ("borders", "Biên giới")):
        field(label, d.get(key, "N/A"))

    flag = d.get("flag", {})
    field("Cờ quốc gia", flag.get("emoji", "N/A") if isinstance(flag, dict) else "N/A")

    conn = d.get("connection", {})
    if isinstance(conn, dict):
        field("ASN", conn.get("asn", "N/A"))
        field("Tổ chức", conn.get("org", "N/A"))
        field("Nhà mạng", conn.get("isp", "N/A"))
        field("Tên miền", conn.get("domain", "N/A"))
    else:
        field("ASN/Tổ chức/ISP", "N/A")

    tz = d.get("timezone", {})
    if isinstance(tz, dict):
        for key, label in (("id", "ID múi giờ"), ("abbr", "Viết tắt"), ("is_dst", "DST"),
                           ("offset", "Độ lệch"), ("utc", "UTC"),
                           ("current_time", "Giờ hiện tại")):
            field(label, tz.get(key, "N/A"))
    else:
        field("Múi giờ", "N/A")


# ---------------------------------------------------------------- DNS records via DoH
def doh_query(name, rtype):
    try:
        r = requests.get("https://dns.google/resolve",
                         params={"name": name, "type": rtype},
                         timeout=TIMEOUT, headers=HEADERS)
        answers = r.json().get("Answer", [])
        return [a["data"] for a in answers if a.get("type") == DNS_TYPES[rtype]]
    except (requests.RequestException, ValueError, KeyError):
        return None


def dns_records(domain):
    return {rtype: doh_query(domain, rtype) for rtype in DNS_TYPES}


def print_dns_records(records, domain):
    section(f"BẢN GHI DNS: {domain}")
    for rtype, values in records.items():
        if values is None:
            field(rtype, "Lỗi truy vấn", R)
        elif not values:
            field(rtype, "Không có bản ghi", Y)
        else:
            field(rtype, values[0])
            for v in values[1:]:
                print(f" {'':<17} {G} {v}{RS}")


def email_security(domain):
    result = {"domain": domain, "spf": None, "dmarc": None, "error": None}
    txt = doh_query(domain, "TXT")
    dmarc = doh_query(f"_dmarc.{domain}", "TXT")
    if txt is None or dmarc is None:
        result["error"] = "Không truy vấn được DNS"
        return result
    for t in txt:
        t = t.strip('"')
        if t.lower().startswith("v=spf1"):
            result["spf"] = t
    for t in dmarc:
        t = t.strip('"')
        if t.lower().startswith("v=dmarc1"):
            result["dmarc"] = t
    return result


def print_email_security(e):
    section("BẢO MẬT EMAIL (SPF / DMARC)")
    if e["error"]:
        field("Lỗi", e["error"], R)
        return
    if e["spf"]:
        field("SPF", e["spf"])
        if re.search(r"[+?]all\b", e["spf"]):
            field("Đánh giá SPF", "Yếu: chính sách cho phép mọi máy chủ gửi thư", Y)
    else:
        field("SPF", "Không có bản ghi SPF (dễ bị giả mạo email)", R)
    if e["dmarc"]:
        field("DMARC", e["dmarc"])
        m = re.search(r"p=(\w+)", e["dmarc"], re.IGNORECASE)
        if m and m.group(1).lower() == "none":
            field("Đánh giá DMARC", "Chỉ giám sát (p=none), chưa chặn thư giả mạo", Y)
    else:
        field("DMARC", "Không có bản ghi DMARC", R)


# ---------------------------------------------------------------- SSL / TLS
def ssl_info(host, port=443):
    result = {"host": host, "port": port, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls_version"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Chứng chỉ không hợp lệ: {e.verify_message}"
        return result
    except (socket.timeout, socket.error, ssl.SSLError, OSError) as e:
        result["error"] = f"Không kết nối được TLS: {e}"
        return result

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    result["subject_cn"] = subject.get("commonName")
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    result["not_before"] = cert.get("notBefore")
    result["not_after"] = cert.get("notAfter")
    result["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    try:
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        result["days_left"] = int((expires - time.time()) // 86400)
    except (KeyError, ValueError):
        result["days_left"] = None
    return result


def print_ssl_info(s):
    section("CHỨNG CHỈ SSL/TLS")
    field("Máy chủ", f"{s['host']}:{s['port']}")
    if s["error"]:
        field("Lỗi", s["error"], R)
        return
    field("Tên chủ thể (CN)", s.get("subject_cn") or NA)
    field("Nhà cấp phát", s.get("issuer") or NA)
    field("Có hiệu lực từ", s.get("not_before") or NA)
    field("Hết hạn", s.get("not_after") or NA)
    if s.get("days_left") is not None:
        color = R if s["days_left"] < 14 else (Y if s["days_left"] < 30 else G)
        field("Còn lại", f"{s['days_left']} ngày", color)
    field("Phiên bản TLS", s.get("tls_version") or NA)
    field("Bộ mã hóa", s.get("cipher") or NA)
    if s.get("san"):
        field("Tên thay thế (SAN)", ", ".join(s["san"][:10]))
        if len(s["san"]) > 10:
            print(f" {'':<17} {Y} ... và {len(s['san']) - 10} tên khác{RS}")


# ---------------------------------------------------------------- HTTP check
def http_check(host):
    result = {"host": host, "error": None}
    r = None
    for scheme in ("https", "http"):
        try:
            start = time.time()
            r = requests.get(f"{scheme}://{host}", timeout=TIMEOUT, headers=HEADERS,
                             allow_redirects=True)
            result["response_ms"] = int((time.time() - start) * 1000)
            break
        except requests.RequestException as e:
            result["error"] = f"Không kết nối được: {e}"
    if r is None:
        return result
    result["error"] = None
    result["final_url"] = r.url
    result["status"] = r.status_code
    result["redirects"] = [(h.status_code, h.url) for h in r.history]
    result["server"] = r.headers.get("Server")
    result["powered_by"] = r.headers.get("X-Powered-By")
    result["security_headers"] = {h: r.headers.get(h) is not None for h in SECURITY_HEADERS}
    return result


def print_http_check(h):
    section("KIỂM TRA HTTP & HEADER BẢO MẬT")
    field("Tên miền", h["host"])
    if h["error"]:
        field("Lỗi", h["error"], R)
        return
    field("URL cuối cùng", h["final_url"])
    field("Mã trạng thái", h["status"])
    field("Thời gian phản hồi", f"{h['response_ms']} ms")
    field("Máy chủ web", h["server"] or NA)
    if h["powered_by"]:
        field("X-Powered-By", h["powered_by"], Y)
    if h["redirects"]:
        field("Chuyển hướng", " -> ".join(f"{c} {u}" for c, u in h["redirects"]))
    present = sum(h["security_headers"].values())
    field("Header bảo mật", f"{present}/{len(SECURITY_HEADERS)}",
          G if present >= 4 else Y)
    for name, ok in h["security_headers"].items():
        mark = f"{G}CÓ" if ok else f"{R}THIẾU"
        print(f" {'':<17} {W}{name:<27}{mark}{RS}")


# ---------------------------------------------------------------- Phone lookup
def phone_lookup(raw):
    result = {"input": raw, "error": None}
    raw = raw.strip()
    try:
        parsed = phonenumbers.parse(raw, None if raw.startswith("+") else DEFAULT_REGION)
    except phonenumbers.NumberParseException as e:
        result["error"] = f"Số điện thoại không hợp lệ: {e}"
        return result
    fmt = phonenumbers.PhoneNumberFormat
    result.update({
        "valid": phonenumbers.is_valid_number(parsed),
        "possible": phonenumbers.is_possible_number(parsed),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "e164": phonenumbers.format_number(parsed, fmt.E164),
        "international": phonenumbers.format_number(parsed, fmt.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, fmt.NATIONAL),
        "region_code": phonenumbers.region_code_for_number(parsed),
        "location": geocoder.description_for_number(parsed, "vi"),
        "carrier": carrier.name_for_number(parsed, "vi"),
        "timezones": list(pn_timezone.time_zones_for_number(parsed)),
        "type": PHONE_TYPES.get(phonenumbers.number_type(parsed), "Không xác định"),
    })
    return result


def print_phone(p):
    section("THÔNG TIN SỐ ĐIỆN THOẠI")
    field("Đầu vào", p["input"])
    if p["error"]:
        field("Lỗi", p["error"], R)
        return
    field("Hợp lệ", "Có" if p["valid"] else "Không", G if p["valid"] else R)
    field("Có thể tồn tại", "Có" if p["possible"] else "Không")
    field("Định dạng E.164", p["e164"])
    field("Định dạng quốc tế", p["international"])
    field("Định dạng trong nước", p["national"])
    field("Mã quốc gia", f"+{p['country_code']}")
    field("Mã vùng quốc gia", p["region_code"] or NA)
    field("Khu vực", p["location"] or NA)
    field("Nhà mạng", p["carrier"] or NA)
    field("Loại số", p["type"])
    field("Múi giờ", ", ".join(p["timezones"]) if p["timezones"] else NA)
    print(f"\n {Y}[!] Nhà mạng là đơn vị cấp số ban đầu, có thể đã chuyển mạng giữ số.{RS}")
    print(f" {Y}[!] Công cụ chỉ cho biết thông tin kỹ thuật, không xác định chủ thuê bao.{RS}")


# ---------------------------------------------------------------- Email helpers
def addr_domain(value):
    m = re.search(r"@([\w.\-]+)", value or "")
    return m.group(1).lower() if m else None


def email_check(address):
    address = address.strip()
    result = {"input": address, "valid_syntax": False, "domain": None,
              "mx": None, "spf": None, "dmarc": None, "error": None}
    if not EMAIL_RE.match(address):
        result["error"] = "Định dạng email không hợp lệ"
        return result
    result["valid_syntax"] = True
    domain = to_ascii_domain(address.rsplit("@", 1)[1])
    result["domain"] = domain
    result["mx"] = doh_query(domain, "MX")
    sec = email_security(domain)
    result["spf"], result["dmarc"] = sec["spf"], sec["dmarc"]
    return result


def print_email_check(e):
    section("KIỂM TRA EMAIL")
    field("Email", e["input"])
    if e["error"]:
        field("Lỗi", e["error"], R)
        return
    field("Định dạng", "Hợp lệ")
    field("Tên miền email", e["domain"])
    if e["mx"] is None:
        field("Máy chủ mail (MX)", "Lỗi truy vấn", R)
    elif not e["mx"]:
        field("Máy chủ mail (MX)", "Không có MX: tên miền này không nhận được thư", R)
    else:
        field("Máy chủ mail (MX)", e["mx"][0])
        for mx in e["mx"][1:]:
            print(f" {'':<17} {G} {mx}{RS}")
    field("SPF", e["spf"] or "Không có", None if e["spf"] else Y)
    field("DMARC", e["dmarc"] or "Không có", None if e["dmarc"] else Y)


def email_breach_check(address):
    address = address.strip()
    result = {"email": address, "valid_syntax": False,
              "emailrep": None, "holehe": None, "error": None}
    if not EMAIL_RE.match(address):
        result["error"] = "Định dạng email không hợp lệ"
        return result
    result["valid_syntax"] = True

    # --- EmailRep ---
    try:
        r = requests.get(
            f"https://emailrep.io/{address}",
            headers={"User-Agent": "GhostTR-OSINT/1.0"},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            details = data.get("details", {}) or {}
            result["emailrep"] = {
                "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"),
                "references": data.get("references"),
                "credentials_leaked": details.get("credentials_leaked"),
                "credentials_leaked_recent": details.get("credentials_leaked_recent"),
                "data_breach": details.get("data_breach"),
                "first_seen": details.get("first_seen"),
                "last_seen": details.get("last_seen"),
                "profiles": details.get("profiles", []),
                "blacklisted": details.get("blacklisted"),
                "malicious_activity": details.get("malicious_activity"),
            }
    except (requests.RequestException, ValueError):
        pass

    # --- Holehe (chạy real-time, in log ra màn hình) ---
    try:
        print(f"\n {Y}[*] Đang chạy Holehe (quá trình này mất 30-90 giây)...{RS}")
        # Dùng Popen thay vì run để đọc log liên tục
        proc = subprocess.Popen(
            ["holehe", address, "--only-used"],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )
        
        found = []
        # Đọc từng dòng ngay khi Holehe vừa in ra
        for line in proc.stdout:
            print(line, end="")  # In thẳng ra màn hình cho mày xem
            m = re.search(r"\[\+\]\s+Email used on\s+(.+)", line, re.IGNORECASE)
            if m:
                found.append(m.group(1).strip())
                
        proc.wait()
        result["holehe"] = {"found": found, "count": len(found)}
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return result


def print_email_breach(b):
    section(f"KIỂM TRA RÒ RỈ DỮ LIỆU: {b['email']}")
    if b["error"]:
        field("Lỗi", b["error"], R)
        return

    er = b.get("emailrep")
    if er:
        if er.get("credentials_leaked"):
            field("Thông tin đăng nhập bị lộ", "CÓ", R)
        if er.get("credentials_leaked_recent"):
            field("Lộ gần đây (90 ngày)", "CÓ", R)
        if er.get("data_breach"):
            field("Xuất hiện trong vụ rò rỉ", "CÓ", R)
        if er.get("profiles"):
            field("Hồ sơ MXH từng thấy", ", ".join(er["profiles"][:10]))
        if er.get("first_seen") and er["first_seen"] != "never":
            field("Lần đầu thấy", er["first_seen"])
        if er.get("last_seen") and er["last_seen"] != "never":
            field("Lần cuối thấy", er["last_seen"])
        if er.get("blacklisted"):
            field("Blacklist", "CÓ", R)
        if er.get("malicious_activity"):
            field("Hoạt động độc hại", "CÓ", R)
        if not any([er.get("credentials_leaked"), er.get("data_breach"),
                    er.get("profiles"), er.get("blacklisted"),
                    er.get("malicious_activity")]):
            print(f" {Y}EmailRep: không tìm thấy dấu vết rò rỉ.{RS}")

    hh = b.get("holehe")
    if hh:
        if hh["found"]:
            field("Tài khoản tìm thấy (Holehe)", f"{hh['count']}")
            for name in hh["found"]:
                print(f" {W}[{G}+{W}] {name}{RS}")
        else:
            print(f" {Y}Holehe: không tìm thấy tài khoản nào.{RS}")


def analyze_headers(raw):
    msg = HeaderParser().parsestr(raw)
    result = {
        "from": msg.get("From"), "to": msg.get("To"), "subject": msg.get("Subject"),
        "date": msg.get("Date"), "return_path": msg.get("Return-Path"),
        "reply_to": msg.get("Reply-To"), "message_id": msg.get("Message-ID"),
        "auth_results": [" ".join(h.split()) for h in (msg.get_all("Authentication-Results") or [])],
        "hops": [], "origin_geo": [], "warnings": [], "error": None,
    }
    received = msg.get_all("Received") or []
    if not received and not result["from"]:
        result["error"] = "Không đọc được header email"
        return result

    seen_ips = []
    for h in reversed(received):
        h = " ".join(h.split())
        candidates = (re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", h)
                      + re.findall(r"\[([0-9a-fA-F:]{3,})\]", h))
        public = []
        for ip in candidates:
            if is_ip(ip) and ipaddress.ip_address(ip).is_global and ip not in public:
                public.append(ip)
        result["hops"].append({"raw": h[:160], "public_ips": public})
        for ip in public:
            if ip not in seen_ips:
                seen_ips.append(ip)

    for i, ip in enumerate(seen_ips[:3]):
        result["origin_geo"].append(ip_geolocation(ip))
        if i < len(seen_ips[:3]) - 1:
            time.sleep(1)

    from_d = addr_domain(result["from"])
    reply_d = addr_domain(result["reply_to"])
    path_d = addr_domain(result["return_path"])
    if from_d and reply_d and from_d != reply_d:
        result["warnings"].append(f"Reply-To ({reply_d}) khác miền người gửi ({from_d})")
    if from_d and path_d and from_d != path_d:
        result["warnings"].append(f"Return-Path ({path_d}) khác miền người gửi ({from_d})")
    for ar in result["auth_results"]:
        for mech in ("spf", "dkim", "dmarc"):
            if re.search(rf"\b{mech}=(fail|softfail|none|permerror|temperror)", ar, re.IGNORECASE):
                warn = f"Xác thực {mech.upper()} không đạt"
                if warn not in result["warnings"]:
                    result["warnings"].append(warn)
    return result


def print_header_analysis(h):
    section("PHÂN TÍCH HEADER EMAIL")
    if h["error"]:
        field("Lỗi", h["error"], R)
        return
    for key, label in (("from", "Từ"), ("to", "Đến"), ("subject", "Tiêu đề"),
                       ("date", "Ngày gửi"), ("return_path", "Return-Path"),
                       ("reply_to", "Reply-To"), ("message_id", "Message-ID")):
        field(label, h[key] or NA)
    for ar in h["auth_results"]:
        field("Xác thực", ar[:110])
    print(f"\n {W}Hành trình thư (từ nơi gửi đầu tiên):{RS}")
    for i, hop in enumerate(h["hops"], 1):
        print(f" {W}#{i:<2}{G} {hop['raw']}{RS}")
        if hop["public_ips"]:
            print(f"     {W}IP công khai: {G}{', '.join(hop['public_ips'])}{RS}")
    if h["origin_geo"]:
        print(f"\n {W}Vị trí các IP đầu tiên trong hành trình:{RS}")
        for g in h["origin_geo"]:
            if g.get("error"):
                field(g["ip"], g["error"], R)
            else:
                conn = g.get("connection", {}) if isinstance(g.get("connection"), dict) else {}
                field(g["ip"], f"{g.get('city', 'N/A')}, {g.get('country', 'N/A')} - {conn.get('isp', 'N/A')}")
    if h["warnings"]:
        print(f"\n {Y}Cảnh báo:{RS}")
        for w in h["warnings"]:
            print(f" {Y}- {w}{RS}")
    else:
        print(f"\n {G}Không phát hiện dấu hiệu bất thường rõ ràng.{RS}")


# ---------------------------------------------------------------- image EXIF geolocation
def _dms_to_degrees(dms):
    try:
        d = float(dms[0])
        m = float(dms[1])
        s = float(dms[2]) if len(dms) > 2 else 0.0
        return d + m / 60.0 + s / 3600.0
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _rational_to_float(value):
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return value[0] / value[1] if value[1] else None
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _convert_gps(gps_raw):
    out = {"lat": None, "lon": None, "altitude": None,
           "timestamp": None, "datestamp": None, "direction": None}
    gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}

    lat_dms = gps.get("GPSLatitude")
    lat_ref = gps.get("GPSLatitudeRef")
    lon_dms = gps.get("GPSLongitude")
    lon_ref = gps.get("GPSLongitudeRef")

    if lat_dms and lat_ref:
        deg = _dms_to_degrees(lat_dms)
        if deg is not None:
            if str(lat_ref).upper().startswith("S"):
                deg = -deg
            out["lat"] = deg
    if lon_dms and lon_ref:
        deg = _dms_to_degrees(lon_dms)
        if deg is not None:
            if str(lon_ref).upper().startswith("W"):
                deg = -deg
            out["lon"] = deg

    alt = gps.get("GPSAltitude")
    alt_ref = gps.get("GPSAltitudeRef")
    if alt is not None:
        val = _rational_to_float(alt)
        if val is not None:
            if alt_ref in (1, b"\x01"):
                val = -val
            out["altitude"] = val

    out["timestamp"] = gps.get("GPSTimeStamp")
    out["datestamp"] = gps.get("GPSDateStamp")
    direction = gps.get("GPSImgDirection")
    if direction is not None:
        out["direction"] = _rational_to_float(direction)
    return out


def exif_geolocation(path):
    result = {
        "path": path, "exists": False, "error": None,
        "format": None, "size": None, "mode": None,
        "camera_make": None, "camera_model": None, "software": None,
        "datetime_original": None, "datetime_digitized": None,
        "lat": None, "lon": None, "altitude": None,
        "gps_timestamp": None, "gps_datestamp": None, "direction": None,
        "maps_url": None, "raw_exif": {},
    }
    if not PIL_AVAILABLE:
        result["error"] = "Thiếu thư viện Pillow. Cài bằng: pip install pillow"
        return result

    if not os.path.exists(path):
        result["error"] = f"Không tìm thấy file: {path}"
        return result
    result["exists"] = True

    try:
        with Image.open(path) as img:
            result["format"] = img.format
            result["size"] = f"{img.width}x{img.height}"
            result["mode"] = img.mode
            exif = img.getexif()
            gps_ifd = None
            try:
                gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else exif.get(0x8825)
            except (KeyError, AttributeError):
                gps_ifd = exif.get(0x8825)

            if not exif and not gps_ifd:
                result["error"] = "Ảnh không có dữ liệu EXIF"
                return result

            tag_map = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
            result["camera_make"] = tag_map.get("Make")
            result["camera_model"] = tag_map.get("Model")
            result["software"] = tag_map.get("Software")
            result["datetime_original"] = tag_map.get("DateTimeOriginal")
            result["datetime_digitized"] = tag_map.get("DateTimeDigitized")

            for k, v in tag_map.items():
                if isinstance(v, (str, int, float)):
                    result["raw_exif"][k] = v
                else:
                    result["raw_exif"][k] = str(v)

            if gps_ifd:
                gps_conv = _convert_gps(gps_ifd)
                result["lat"] = gps_conv["lat"]
                result["lon"] = gps_conv["lon"]
                result["altitude"] = gps_conv["altitude"]
                result["gps_timestamp"] = str(gps_conv["timestamp"]) if gps_conv["timestamp"] else None
                result["gps_datestamp"] = str(gps_conv["datestamp"]) if gps_conv["datestamp"] else None
                result["direction"] = gps_conv["direction"]
                if result["lat"] is not None and result["lon"] is not None:
                    result["maps_url"] = (
                        f"https://www.google.com/maps?q={result['lat']},{result['lon']}"
                    )
    except (OSError, ValueError) as e:
        result["error"] = f"Không đọc được ảnh: {e}"
    return result


def print_exif_geolocation(g):
    section("TOẠ ĐỘ TỪ ẢNH (EXIF GPS)")
    field("Đường dẫn", g["path"])
    if g["error"]:
        field("Lỗi", g["error"], R)
        return
    field("Định dạng", g["format"] or NA)
    field("Kích thước", g["size"] or NA)
    field("Chế độ màu", g["mode"] or NA)
    if g["camera_make"] or g["camera_model"]:
        field("Máy ảnh", f"{g['camera_make'] or ''} {g['camera_model'] or ''}".strip())
    if g["software"]:
        field("Phần mềm", g["software"])
    if g["datetime_original"]:
        field("Ngày chụp", g["datetime_original"])
    if g["datetime_digitized"]:
        field("Ngày số hoá", g["datetime_digitized"])

    if g["lat"] is None or g["lon"] is None:
        field("Toạ độ GPS", "Không có trong EXIF ảnh", Y)
        print(f"\n {Y}[!] Ảnh có thể đã bị xoá EXIF hoặc không được gắn GPS khi chụp.{RS}")
        return

    field("Vĩ độ", f"{g['lat']:.6f}")
    field("Kinh độ", f"{g['lon']:.6f}")
    if g["altitude"] is not None:
        field("Độ cao", f"{g['altitude']:.1f} m")
    if g["direction"] is not None:
        field("Hướng chụp", f"{g['direction']:.1f}°")
    if g["gps_datestamp"]:
        field("Ngày GPS", g["gps_datestamp"])
    if g["gps_timestamp"]:
        field("Giờ GPS (UTC)", g["gps_timestamp"])
    field("Bản đồ", g["maps_url"])
    print(f" {W}{'OpenStreetMap':<17}:{G} "
          f"https://www.openstreetmap.org/?mlat={g['lat']}&mlon={g['lon']}#map=17/{g['lat']}/{g['lon']}{RS}")


# ---------------------------------------------------------------- Social media lookup
def check_social(username):
    results = []
    for site in SOCIAL_MEDIA:
        url = site["url"].format(username)
        entry = {"name": site["name"], "url": url, "exists": None, "status": None}
        try:
            r = requests.get(url, timeout=8, headers=HEADERS, allow_redirects=True)
            entry["status"] = r.status_code
            if r.status_code == 200:
                body = r.text.lower()
                if any(k in body for k in ("page not found", "user not found",
                                           "không tìm thấy", "sorry, this page",
                                           "this account doesn't exist", "profile not found",
                                           "account suspended", "no longer available")):
                    entry["exists"] = False
                else:
                    entry["exists"] = True
            elif r.status_code == 404:
                entry["exists"] = False
            else:
                entry["exists"] = None
        except requests.RequestException:
            entry["exists"] = None
        results.append(entry)
        time.sleep(0.3)
    return results


def print_social(results, username):
    section(f"TÀI KHOẢN MẠNG XÃ HỘI: {username}")
    found = [r for r in results if r["exists"] is True]
    unknown = [r for r in results if r["exists"] is None]
    field("Tìm thấy", f"{len(found)}/{len(results)}", G if found else Y)
    for r in found:
        print(f" {W}[{G}+{W}] {r['name']:<18}{G} {r['url']}{RS}")
    if unknown:
        print(f"\n {Y}Không xác định (bị chặn / lỗi mạng):{RS}")
        for r in unknown:
            print(f" {Y}[?] {r['name']:<18}{G} {r['url']}{RS}")
    print(f"\n {Y}[!] Chỉ kiểm tra sự tồn tại của URL công khai, không truy cập dữ liệu riêng tư.{RS}")


# ---------------------------------------------------------------- Menu actions
@is_option
def IP_Track():
    target = normalize_target(input(f"{W}\n Nhập IP hoặc tên miền cần tra : {G}"))
    print()

    res = resolve_target(target)
    if not res["is_ip"] and not res["ipv4"] and not res["ipv6"]:
        print(f"{R} Lỗi: Không phân giải được tên miền hoặc IP không hợp lệ: {target}{RS}")
        return

    print_resolution(res)
    report = {"target": target, "resolution": res, "ips": [], "whois": []}
    ip_list = res["ipv4"] or res["ipv6"] or [target]

    if res["is_ip"]:
        for ip in ip_list:
            ip_report = {"ip": ip}
            rev = reverse_dns(ip)
            print_reverse_dns(rev)
            ip_report["reverse_dns"] = rev

            found = find_domain_from_ip(ip, rev)
            ip_report["domain_lookup"] = found
            section("TÌM TÊN MIỀN TỪ IP")
            field("PTR", found["ptr"] or NA)
            field("ipwho.is", found["ipwho_domain"] or NA)
            field("ipapi.co (tổ chức)", found["ipapi_org"] or NA)
            field("RDAP (tên mạng)", found["rdap_name"] or NA)
            if found["suggestions"]:
                field("Tên miền gợi ý", ", ".join(found["suggestions"]))
                for g in found["suggestions"][:3]:
                    try:
                        _, _, g_ips = socket.gethostbyname_ex(g)
                        status = "KHỚP" if ip in g_ips else "KHÔNG KHỚP"
                        field("Xác minh", f"{g} -> {', '.join(g_ips)} [{status}]")
                    except (socket.gaierror, UnicodeError):
                        field("Xác minh", f"{g} -> {R}Không phân giải được{RS}")

            contacts = contacts_from_ip(ip)
            ip_report["contacts"] = contacts
            section("LIÊN HỆ TỪ IP (RDAP)")
            field("Tên mạng", contacts["network_name"] or NA)
            field("Quốc gia", contacts["country"] or NA)
            if contacts["orgs"]:
                field("Tổ chức", ", ".join(contacts["orgs"][:5]))
            field("Email", ", ".join(contacts["emails"][:5]) or "Không có (bị ẩn)")
            field("Số điện thoại", ", ".join(contacts["phones"][:5]) or "Không có (bị ẩn)")

            for g in found["suggestions"][:2]:
                w = parse_whois(whois_domain(g), g)
                print_whois(w)
                report["whois"].append(w)
            report["ips"].append(ip_report)
    else:
        report["dns"] = dns_records(target)
        print_dns_records(report["dns"], target)

        report["email_security"] = email_security(target)
        print_email_security(report["email_security"])

        report["ssl"] = ssl_info(target)
        print_ssl_info(report["ssl"])

        report["http"] = http_check(target)
        print_http_check(report["http"])

        rev = reverse_dns(ip_list[0])
        print_reverse_dns(rev)
        report["reverse_dns"] = rev
        domain = registrable_domain(res["canonical"] or target)
        w = parse_whois(whois_domain(domain), domain)
        print_whois(w)
        report["whois"].append(w)

    section("HIỂN THỊ THÔNG TIN ĐỊA CHỈ IP")
    field("Mục tiêu", target)

    report["geolocation"] = []
    max_trace = min(len(ip_list), 5)
    for i in range(max_trace):
        geo = ip_geolocation(ip_list[i])
        print_geolocation(geo)
        report["geolocation"].append(geo)
        if i < max_trace - 1:
            time.sleep(1)
    if len(ip_list) > 5:
        print(f"\n {Y}[!] Chỉ truy vết 5/{len(ip_list)} IP đầu tiên để tránh rate limit{RS}")

    ask_save(report, target)


@is_option
def phoneGW():
    raw = input(f"\n {W}Nhập số điện thoại cần tra (vd: +84901234567 hoặc 0901234567) : {G}")
    info = phone_lookup(raw)
    print_phone(info)
    ask_save(info, re.sub(r"\D", "", raw) or "phone")


@is_option
def DNS_Records_Email():
    """Chỉ tra DNS + SPF/DMARC cho tên miền."""
    host = ask_domain()
    if not host:
        return

    report = {"domain": host}

    report["dns"] = dns_records(host)
    print_dns_records(report["dns"], host)

    report["email_security"] = email_security(host)
    print_email_security(report["email_security"])

    ask_save(report, host)


@is_option
def Email_Only():
    """Chỉ kiểm tra email: định dạng, MX, SPF/DMARC, rò rỉ, header."""
    address = input(f"\n {W}Nhập địa chỉ email cần kiểm tra : {G}").strip()
    if not address:
        print(f" {R}Địa chỉ email không được để trống.{RS}")
        return
    if not EMAIL_RE.match(address):
        print(f" {R}Định dạng email không hợp lệ.{RS}")
        return

    report = {"email": address}

    info = email_check(address)
    print_email_check(info)
    report["email_check"] = info

    breach = email_breach_check(address)
    report["email_breach"] = breach
    print_email_breach(breach)

    analyze = input(
        f"\n {W}Phân tích header email? (y/N): {G}"
    ).strip().lower()
    if analyze == "y":
        raw_headers = read_multiline(
            f"\n {W}Dán toàn bộ header email, kết thúc bằng một dòng chỉ có END:{G}"
        )
        header_info = analyze_headers(raw_headers)
        print_header_analysis(header_info)
        report["header_analysis"] = header_info

    ask_save(report, re.sub(r"[^\w.-]", "_", address) or "email")


@is_option
def SSL_Check():
    host = ask_domain()
    if not host:
        return
    info = ssl_info(host)
    print_ssl_info(info)
    ask_save(info, host)


@is_option
def HTTP_Check():
    host = ask_domain()
    if not host:
        return
    info = http_check(host)
    print_http_check(info)
    ask_save(info, host)


@is_option
def Image_Geolocation():
    path = input(
        f"\n {W}Nhập đường dẫn ảnh (vd: /storage/emulated/0/Download/tenanh.png) : {G}"
    ).strip()
    if path.startswith("file://"):
        path = path[7:]
    path = os.path.expanduser(path)
    info = exif_geolocation(path)
    print_exif_geolocation(info)
    if info.get("lat") is not None and info.get("lon") is not None:
        print(f"\n {G}Đã trích xuất được toạ độ từ ảnh.{RS}")
    else:
        print(f"\n {Y}Không trích xuất được toạ độ GPS từ ảnh này.{RS}")
    ask_save(info, os.path.basename(path) or "image_exif")


@is_option
def Social_Lookup():
    username = input(f"\n {W}Nhập tên đăng nhập cần tìm : {G}").strip()
    if not username:
        print(f" {R}Tên đăng nhập không được để trống.{RS}")
        return
    if not re.match(r"^[A-Za-z0-9._\-]{2,50}$", username):
        print(f" {R}Tên đăng nhập chứa ký tự không hợp lệ.{RS}")
        return
    results = check_social(username)
    print_social(results, username)
    ask_save({"username": username, "results": results}, f"social_{username}")


# ---------------------------------------------------------------- Main menu
def main():
    actions = {
        "1": IP_Track,
        "2": phoneGW,
        "3": DNS_Records_Email,
        "4": Email_Only,
        "5": SSL_Check,
        "6": HTTP_Check,
        "7": Image_Geolocation,
        "8": Social_Lookup,
    }
    while True:
        run_banner()
        print(f" {W}[{G}1{W}] Tra cứu IP / tên miền (đầy đủ: DNS, SSL, HTTP, WHOIS)")
        print(f" {W}[{G}2{W}] Tra cứu số điện thoại")
        print(f" {W}[{G}3{W}] Bản ghi DNS & bảo mật email (SPF/DMARC) theo tên miền")
        print(f" {W}[{G}4{W}] Kiểm tra email (định dạng, MX, rò rỉ, header)")
        print(f" {W}[{G}5{W}] Chứng chỉ SSL/TLS")
        print(f" {W}[{G}6{W}] Kiểm tra HTTP & header bảo mật")
        print(f" {W}[{G}7{W}] Toạ độ GPS từ ảnh (EXIF)")
        print(f" {W}[{G}8{W}] Tìm tài khoản mạng xã hội theo username (~90 trang)")
        print(f" {W}[{R}0{W}] Thoát")
        try:
            choice = input(f"\n {W}Chọn chức năng: {G}").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if choice == "0":
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print(f" {R}Lựa chọn không hợp lệ.{RS}")
            time.sleep(1)
    print(f"\n {W}Tạm biệt!{RS}\033[0m")


if __name__ == "__main__":
    main()