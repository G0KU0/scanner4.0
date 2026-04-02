"""
DEBUG2 - Megnezi a teljes $Config tartalmat es menti az oldalt fajlba.
Futtasd: python debug2.py
"""
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = (
    'https://login.live.com/oauth20_authorize.srf?'
    'client_id=00000000402B5328&'
    'redirect_uri=https://login.live.com/oauth20_desktop.srf&'
    'scope=service::user.auth.xboxlive.com::MBI_SSL&'
    'display=touch&response_type=token&locale=en'
)

session = requests.Session()
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}

r = session.get(url, headers=headers, timeout=15, verify=False)
text = r.text

# HTML mentese fajlba
with open('login_page.html', 'w', encoding='utf-8') as f:
    f.write(text)
print(f"HTML mentve: login_page.html ({len(text)} karakter)")

# urlPost korul nez
idx = text.find('"urlPost"')
if idx != -1:
    context_start = max(0, idx - 500)
    context_end = min(len(text), idx + 500)
    print(f"\n=== urlPost korul (+/-500 char) ===")
    print(text[context_start:context_end])
    print("=== VEGE ===")
else:
    print("urlPost nem talalhato!")

# $Config keresese
print("\n=== $Config keresese ===")
m = re.search(r'\$Config\s*=\s*(\{.{0,3000}?\});', text, re.S)
if m:
    config = m.group(1)
    print(f"$Config talalva! ({len(config)} char)")
    print(config[:2000])
else:
    print("$Config nem talalhato direkt formaban, proba mas pattern...")
    # Proba escaped verzio
    m2 = re.search(r'Config\.setData\((\{.{0,3000}?\})\)', text, re.S)
    if m2:
        print("Config.setData talalva!")
        print(m2.group(1)[:2000])
    else:
        # Keress barmilyen PPFT-re emlekeztet stringet
        for kw in ['sFT', 'PPFT', 'ppft', 'iToken', 'sCtx', 'iPpft', 'sFTTag']:
            positions = [m.start() for m in re.finditer(re.escape(kw), text)]
            if positions:
                print(f"\n'{kw}' talalható {len(positions)} helyen, elso kontextusa:")
                idx = positions[0]
                print(text[max(0,idx-50):idx+200])

# value= keresese (eredeti kod mintajara)
print("\n=== Elso 5 value= elofordulas ===")
matches = list(re.finditer(r'value="([^"]{10,})"', text))
for i, m in enumerate(matches[:5]):
    print(f"  [{i+1}] pos={m.start()}: value=\"{m.group(1)[:60]}...\"")

input("\nNyomj Entert a kilépéshez...")
