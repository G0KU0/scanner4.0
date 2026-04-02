import re

with open('login_page.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Pontosan ugyanaz a pattern amit a checker.py-ban hasznalunk
m = re.search(r'"sFTTag":".*?value=\\"([^\\"]+)\\"', text, re.S)
print('checker.py sFTTag pattern:', 'TALALT: ' + m.group(1)[:60] + '...' if m else 'NEM TALALT - HIBA!')

mu = re.search(r'"urlPost":"([^"]+)"', text)
print('urlPost:', 'TALALT' if mu else 'NEM - HIBA!')

if m and mu:
    print('\n>>> MINDKETTO TALALT - A JAVITAS MUKODIK! <<<')
    print('Token (elso 30 char):', m.group(1)[:30])
