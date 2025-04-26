import argparse
import requests
import urllib.parse
import random
import string
from bs4 import BeautifulSoup

def generate_payload():
    marker = ''.join(random.choices(string.ascii_letters, k=8))
    payload = f'\"<script>alert({marker})</script>'
    return payload, marker

def inject_and_check(url, param):
    payload, marker = generate_payload()
    parsed_url = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed_url.query))
    query[param] = payload
    new_query = urllib.parse.urlencode(query)
    new_url = parsed_url._replace(query=new_query).geturl()

    try:
        response = requests.get(new_url, timeout=10, verify=False)
        if marker in response.text:
            return True, new_url
    except requests.RequestException:
        pass

    return False, None

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())

def find_forms(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException:
        return []

def form_injection(url, forms):
    vulnerable = []
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}

        for inp in inputs:
            name = inp.get('name')
            if name:
                payload, marker = generate_payload()
                data[name] = payload

        form_url = urllib.parse.urljoin(url, action)

        try:
            if method == 'post':
                resp = requests.post(form_url, data=data, timeout=10, verify=False)
            else:
                resp = requests.get(form_url, params=data, timeout=10, verify=False)

            if any(payload in resp.text for payload in data.values()):
                vulnerable.append(form_url)
        except requests.RequestException:
            continue

    return vulnerable

def main():
    parser = argparse.ArgumentParser(description="Reflective XSS (rXSS) Detection Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL to test")
    parser.add_argument("-f", "--full", action='store_true', help="Test forms along with GET parameters")
    args = parser.parse_args()

    print("[+] Starting XSS scan on:", args.url)

    params = extract_params(args.url)
    if not params:
        print("[-] No query parameters found in URL.")
    else:
        for param in params:
            found, attack_url = inject_and_check(args.url, param)
            if found:
                print(f"[!] Vulnerable parameter detected: {param}")
                print(f"    Payload URL: {attack_url}")
            else:
                print(f"[-] {param} not vulnerable.")

    if args.full:
        print("\n[+] Scanning forms...")
        forms = find_forms(args.url)
        vulnerable_forms = form_injection(args.url, forms)

        if vulnerable_forms:
            for vf in vulnerable_forms:
                print(f"[!] Vulnerable form action detected: {vf}")
        else:
            print("[-] No vulnerable forms detected.")

if __name__ == "__main__":
    main()
