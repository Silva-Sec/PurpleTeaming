import requests
import ssl
import socket
from urllib.parse import urlparse
import sys
import datetime
import os # <-- Adicionado import

# --- Color Constants for the Terminal ---
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_http_redirect(hostname):
    """Checks if HTTP redirects to HTTPS."""
    print(f"{BLUE}[INFO]{RESET} Checking HTTP -> HTTPS redirect...")
    http_url = f"http://{hostname}"
    try:
        response = requests.get(http_url, timeout=10, allow_redirects=False, verify=False)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith(f"https://{hostname}"):
                print(f"{GREEN}[PASS]{RESET} HTTP correctly redirects to HTTPS.")
                return True
        print(f"{RED}[FAIL]{RESET} HTTP does not redirect to HTTPS. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}[WARN]{RESET} Could not connect via HTTP to check redirect: {e}")
    return False

def check_ssl_certificate(hostname):
    """Checks SSL certificate validity, expiration period, and hostname match."""
    print(f"{BLUE}[INFO]{RESET} Checking SSL certificate...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                print(f"{GREEN}[PASS]{RESET} Hostname '{hostname}' matches the SSL certificate.")

                not_after_str = cert['notAfter']
                not_before_str = cert['notBefore']
                date_format = '%b %d %H:%M:%S %Y %Z'
                valid_from = datetime.datetime.strptime(not_before_str, date_format)
                valid_to = datetime.datetime.strptime(not_after_str, date_format)
                validity_period = (valid_to - valid_from).days
                
                if validity_period <= 398:
                    print(f"{GREEN}[PASS]{RESET} SSL validity period is {validity_period} days (within the 398-day limit).")
                else:
                    print(f"{RED}[FAIL]{RESET} SSL validity period is longer than 398 days ({validity_period} days).")
                    
    except ssl.SSLCertVerificationError as e:
        print(f"{RED}[FAIL]{RESET} Hostname does not match the SSL certificate: {e}")
    except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
        print(f"{YELLOW}[WARN]{RESET} Could not connect to the host to check SSL: {e}")
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Unexpected error while checking SSL: {e}")

def check_hsts_preload(hostname):
    """Checks if the domain is on the HSTS preload list."""
    print(f"{BLUE}[INFO]{RESET} Checking HSTS Preload List...")
    api_url = f"https://hstspreload.org/api/v2/status?domain={hostname}"
    try:
        response = requests.get(api_url, timeout=10)
        status = response.json().get('status')
        if status in ['preloaded', 'pending']:
            print(f"{GREEN}[PASS]{RESET} Domain status is '{status}' on the HSTS Preload List.")
        else:
            print(f"{RED}[FAIL]{RESET} Domain is not preloaded or pending. Status: {status}")
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}[WARN]{RESET} Could not query the HSTS Preload API: {e}")

def analyze_headers(url):
    """Analyzes the security headers of the URL."""
    print(f"{BLUE}[INFO]{RESET} Analyzing security headers...")
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        csp = headers.get('Content-Security-Policy')
        if not csp:
            print(f"{RED}[FAIL]{RESET} CSP is not implemented.")
        else:
            print(f"{GREEN}[PASS]{RESET} CSP is implemented.")
            if 'unsafe-eval' in csp:
                print(f"{RED}[FAIL]{RESET} CSP contains unsafe-eval.")
            else:
                print(f"{GREEN}[PASS]{RESET} CSP does not contain 'unsafe-eval'.")
            if 'unsafe-inline' in csp:
                 print(f"{YELLOW}[WARN]{RESET} CSP implemented unsafely (contains 'unsafe-inline').")
            else:
                 print(f"{GREEN}[PASS]{RESET} CSP does not contain 'unsafe-inline'.")

        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            print(f"{RED}[FAIL]{RESET} HTTP Strict Transport Security (HSTS) not enforced.")
        else:
            print(f"{GREEN}[PASS]{RESET} HSTS is enforced.")
            if 'includeSubDomains' in hsts:
                print(f"{GREEN}[PASS]{RESET} HSTS header contains 'includeSubDomains'.")
            else:
                print(f"{RED}[FAIL]{RESET} HSTS header does not contain 'includeSubDomains'.")
        
        cookies = response.cookies
        if not cookies:
            print(f"{BLUE}[INFO]{RESET} No cookies were set in the initial response.")
        else:
            secure_ok = all(c.secure for c in cookies)
            httponly_ok = all(c.has_nonstandard_attr('HttpOnly') or 'httponly' in str(c).lower() for c in cookies)

            if secure_ok:
                print(f"{GREEN}[PASS]{RESET} All cookies use the 'Secure' attribute.")
            else:
                print(f"{RED}[FAIL]{RESET} Secure cookies not used (at least one cookie is not 'secure').")

            if httponly_ok:
                print(f"{GREEN}[PASS]{RESET} All cookies use the 'HttpOnly' attribute.")
            else:
                print(f"{RED}[FAIL]{RESET} HttpOnly cookies not used (at least one cookie is not 'HttpOnly').")

        server_header = headers.get('Server')
        if server_header:
            print(f"{RED}[FAIL]{RESET} Server information header exposed: {server_header}")
        else:
            print(f"{GREEN}[PASS]{RESET} The 'Server' header is not exposed.")
            
        x_content_type = headers.get('X-Content-Type-Options')
        if x_content_type and x_content_type.lower() == 'nosniff':
            print(f"{GREEN}[PASS]{RESET} X-Content-Type-Options is set to 'nosniff'.")
        else:
            print(f"{RED}[FAIL]{RESET} X-Content-Type-Options is not 'nosniff'. Value: {x_content_type}")
            
        x_frame_options = headers.get('X-Frame-Options')
        if x_frame_options and x_frame_options.lower() in ['deny', 'sameorigin']:
            print(f"{GREEN}[PASS]{RESET} X-Frame-Options is set to '{x_frame_options}'.")
        else:
            print(f"{RED}[FAIL]{RESET} X-Frame-Options is not 'deny' or 'sameorigin'. Value: {x_frame_options}")

    except requests.exceptions.RequestException as e:
        print(f"{RED}[ERROR]{RESET} Could not connect to URL {url}: {e}")

def main():
    # --- LÓGICA MODIFICADA ---
    if len(sys.argv) != 2:
        # Mensagem de uso atualizada para mostrar ambas as opções
        print(f"Usage: python {sys.argv[0]} <urls_file.txt | single_url>")
        sys.exit(1)
        
    cli_input = sys.argv[1]
    urls = []

    # Verifica se o argumento é um arquivo que existe
    if os.path.isfile(cli_input):
        print(f"{BLUE}[INFO]{RESET} Reading URLs from file: {cli_input}")
        try:
            with open(cli_input, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            print(f"{RED}[ERROR]{RESET} Could not read file '{cli_input}': {e}")
            sys.exit(1)
    else:
        # Se não for um arquivo, trata como uma única URL
        print(f"{BLUE}[INFO]{RESET} Scanning single URL: {cli_input}")
        urls = [cli_input]

    if not urls:
        print(f"{YELLOW}[WARN]{RESET} No valid URLs to scan.")
        sys.exit(0)
    # --- FIM DA MODIFICAÇÃO ---

    for original_url in urls:
        print("\n" + "="*50)
        print(f"Analyzing: {original_url}")
        print("="*50)
        
        url_to_parse = original_url
        if '://' not in url_to_parse:
            url_to_parse = f"https://{original_url}"
            
        parsed_url = urlparse(url_to_parse)
        hostname = parsed_url.hostname
        
        if not hostname:
            print(f"{YELLOW}[WARN]{RESET} Invalid URL, skipping: {original_url}")
            continue

        https_url = f"https://{hostname}{parsed_url.path}"

        check_http_redirect(hostname)
        check_ssl_certificate(hostname)
        check_hsts_preload(hostname)
        analyze_headers(https_url)
        
    print("\nScan complete.")

if __name__ == "__main__":
    main()
