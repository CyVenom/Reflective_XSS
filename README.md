# Reflective_XSS_Scanner

**Reflective_XSS_Scanner** is a professional-grade Reflective XSS (rXSS) testing tool.  
It tests parameters and forms against 10,000+ carefully generated payloads with multi-threaded scanning, colorful CLI output, and true positive detection.

---

## ✨ Features

- ✅ **10,000+ Professional Payloads** (Including WAF bypass, encoded, mutated, and advanced payloads)
- ✅ **Multi-threaded** fast scanning (`--threads` option)
- ✅ **Random marker** injection to avoid false positives
- ✅ **Form (POST/GET) scanning** support (`--full` option)
- ✅ **Colorized CLI output** (easier to monitor payloads in real time)
- ✅ **Optional JSON Export** (Coming soon!)
- ✅ **Auto URL Crawler** (Coming soon!)

---

## 🛠 Installation

```bash
# Clone or download the repository
cd Reflective_XSS

# Install required libraries
pip install requests beautifulsoup4
```

## 📦 Payload Generation
```bash
 python3 generate_payloads.py

This will create:
#reflective_xss_payloads.txt
#reflective_xss_payloads.json

✅ Now you have 10,000+ payloads ready.
```

## 🚀 Usage

```bash
 1. Basic XSS Scan (URL parameters only)
python3 reflective_xss_scanner.py -u "https://example.com/page.php?id=123"

 2. Full Scan (parameters + forms)
python3 reflective_xss_scanner.py -u "https://example.com/page.php?id=123" -f

 3. Custom Payload File and Thread Count
python3 reflective_xss_scanner.py -u "https://example.com/page.php?id=123" -p "reflective_xss_payloads.txt" -t 20
```

Option	Description
-u	Target URL
-f	Scan forms (GET/POST)
-p	Custom payloads file
-t	Number of threads (default 10)

## 🎯 Example Output

[+] Loaded 10000 payloads.
[+] Starting XSS scan on: https://example.com/page.php?id=123
[+] Testing parameter: id
[Testing Payload] <script>alert(ABC123)</script>
[Testing Payload] <img src=x onerror=alert(DEF456)>
[Testing Payload] <svg/onload=alert(GHI789)>
...

[!] Vulnerable parameter detected: id
    Payload URL: https://example.com/page.php?id="><svg/onload=alert(MNO987)>
    Payload used: "><svg/onload=alert(MNO987)>


## 📚 Project Structure

Reflective_XSS/
├── generate_payloads.py           # Generate 10,000+ payloads
├── reflective_xss_payloads.txt     # Payloads file (TXT)
├── reflective_xss_payloads.json    # Payloads file (JSON)
├── reflective_xss_scanner.py       # Main scanner
├── README.md                       # Documentation


## ⚡ Future Improvements

- [ ] Auto URL crawler (spider target domain)
- [ ] JSON report export
- [ ] Smart form filling (better context handling)
- [ ] DOM-based XSS detection
- [ ] GUI dashboard mode


## ⚠️ Legal Disclaimer
This tool is made for educational and authorized penetration testing only.
Always have permission before scanning or testing any web application.

## License
This project is licensed under the MIT License. Feel free to reuse and adapt!
