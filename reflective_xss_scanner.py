import argparse
import requests
import urllib.parse
import random
import string
import urllib3
import concurrent.futures
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_payloads(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def random_marker():
    return ''.join(random.choices(string.ascii_letters, k=8))

def inject_and_check(url, param, payload_template, verbose=False):
    marker = random_marker()
    payload = payload_template.replace('1', marker).replace('alert', 'alert')  # Keep structure
    parsed_url = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed_url.query))
    query[param] = payload
    new_query = urllib.parse.urlencode(query)
    new_url = parsed_url._replace(query=new_query).geturl()

    if verbose:
        print(f"\033[96m[Testing Payload]\033[0m {payload} on {new_url}")

    try:
        response = requests.get(new_url, timeout=8, verify=False)
        if marker in response.text:
            print(f"\033[92m[!] Possible Reflection Detected: {new_url}\033[0m")
            return True, new_url, payload
    except requests.RequestException as e:
        if verbose:
            print(f"\033[91m[Error] {e}\033[0m")
        pass

    return False, None, None

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())

def find_forms(url):
    try:
        response = requests.get(url, timeout=8, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')
    except requests.RequestException:
        return []

def form_injection(url, forms, payloads, verbose=False):
    vulnerable = []
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}

        for inp in inputs:
            name = inp.get('name')
            if name:
                data[name] = random.choice(payloads)

        form_url = urllib.parse.urljoin(url, action)

        try:
            if method == 'post':
                resp = requests.post(form_url, data=data, timeout=8, verify=False)
            else:
                resp = requests.get(form_url, params=data, timeout=8, verify=False)

            if any(payload in resp.text for payload in data.values()):
                vulnerable.append(form_url)
                print(f"\033[92m[!] Vulnerable Form Detected: {form_url}\033[0m")
        except requests.RequestException as e:
            if verbose:
                print(f"\033[91m[Error] {e}\033[0m")
            continue

    return vulnerable

def main():
    parser = argparse.ArgumentParser(description="Reflective XSS (rXSS) Detection Tool - Advanced Payloads with Multithreading")
    parser.add_argument("-u", "--url", required=True, help="Target URL to test")
    parser.add_argument("-f", "--full", action='store_true', help="Test forms along with GET parameters")
    parser.add_argument("-p", "--payloads", default="reflective_xss_payloads.txt", help="Payloads file (default: reflective_xss_payloads.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    print(f"[+] Loaded {len(payloads)} payloads.")
    print("[+] Starting XSS scan on:", args.url)

    vulnerable_count = 0
    params = extract_params(args.url)
    if not params:
        print("[-] No query parameters found in URL.")
        return

    for param in params:
        print(f"[+] Testing parameter: {param}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for payload in payloads:
                futures.append(executor.submit(inject_and_check, args.url, param, payload, args.verbose))

            for future in concurrent.futures.as_completed(futures):
                found, attack_url, payload_used = future.result()
                if found:
                    print(f"[!] Vulnerable parameter detected: {param}")
                    print(f"    Payload URL: {attack_url}")
                    print(f"    Payload used: {payload_used}")
                    vulnerable_count += 1
                    break  # Found one, no need to keep testing same param

    if args.full:
        print("\n[+] Scanning forms...")
        forms = find_forms(args.url)
        vulnerable_forms = form_injection(args.url, forms, payloads, args.verbose)

        if vulnerable_forms:
            for vf in vulnerable_forms:
                print(f"[!] Vulnerable form action detected: {vf}")
                vulnerable_count += 1
        else:
            print("[-] No vulnerable forms detected.")

    print(f"\n[+] Scan completed. Found {vulnerable_count} vulnerable item(s).")

if __name__ == "__main__":
    main()
