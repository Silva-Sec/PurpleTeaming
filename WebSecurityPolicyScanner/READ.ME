# Web Security Policy Scanner 🐍

A simple, command-line Python script to scan a list of websites for common security misconfigurations in HTTP headers and SSL/TLS certificates. 

This tool is designed to help developers and system administrators quickly verify that security best practices have been correctly implemented across multiple domains.

## Features ✨

The scanner checks for the following security configurations:

* **✅ HTTP to HTTPS Redirection**: Verifies that the site automatically redirects from `http://` to `https://`.
* **✅ SSL Certificate Validation**:
    * Checks if the hostname matches the certificate's Common Name or Subject Alternative Name.
    * Ensures the certificate's validity period does not exceed 398 days.
* **✅ HSTS Preload List**: Checks if the domain is present on the official HSTS preload list via the `hstspreload.org` API.
* **✅ Content Security Policy (CSP)**:
    * Checks if a CSP is implemented.
    * Warns if dangerous directives like `'unsafe-inline'` or `'unsafe-eval'` are present.
* **✅ HTTP Strict Transport Security (HSTS)**:
    * Verifies the `Strict-Transport-Security` header is present.
    * Ensures the `includeSubDomains` directive is included.
* **✅ Secure Cookie Attributes**:
    * Checks for the `Secure` flag on all cookies.
    * Checks for the `HttpOnly` flag on all cookies.
* **✅ Information Exposure**:
    * Checks if the `Server` header is exposed.
* **✅ Other Security Headers**:
    * Verifies `X-Content-Type-Options` is set to `nosniff`.
    * Verifies `X-Frame-Options` is set to `deny` or `sameorigin`.

---

## Installation ⚙️
1.  **Prerequisites**: Ensure you have Python 3 installed on your system.

2.  **Clone the repository (optional)**:
    ```bash
    git clone <your-repository-url>
    cd <your-repository-directory>
    ```

3.  **Install dependencies**: The script requires the `requests` library.
    ```bash
    pip install requests
    ```
    Or, if you have a `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage 🚀

0.  **Run it directly or via URL LIST from txt file.

    ```bash
    python security_scanner.py github.com
    ```

1.  **Create a URL list**: Create a file named `urls.txt` (or any other name) in the same directory as the script. Add the domains you want to scan, one per line. The script works with or without `http://` or `https://`.

    **Example `urls.txt`:**
    ```
    google.com
    github.com
    my-internal-app.dev
    ```

2.  **Run the scanner**: Execute the script from your terminal, passing the name of your URL file as an argument.

    ```bash
    python security_scanner.py urls.txt
    ```

3.  **Interpret the output**: The script will print a color-coded report to the terminal for each URL.

    * `[PASS]` (Green): The security control is correctly implemented.
    * `[FAIL]` (Red): The security control is missing or misconfigured.
    * `[WARN]` (Yellow): A potential issue was found or a check could not be completed.
    * `[INFO]` (Blue): Informational message about the check being performed.

### Example Output

```
==================================================
Analyzing: github.com
==================================================
[INFO] Checking HTTP -> HTTPS redirect...
[PASS] HTTP correctly redirects to HTTPS.
[INFO] Checking SSL certificate...
[PASS] Hostname 'github.com' matches the SSL certificate.
[PASS] SSL validity period is 365 days (within the 398-day limit).
[INFO] Checking HSTS Preload List...
[PASS] Domain is 'preloaded' on the HSTS Preload List.
[INFO] Analyzing security headers...
[PASS] CSP is implemented.
[PASS] CSP does not contain 'unsafe-eval'.
[PASS] CSP does not contain 'unsafe-inline'.
[PASS] HSTS is enforced.
[PASS] HSTS header contains 'includeSubDomains'.
...and so on for all checks.
```
---

## Contributing 🤝

Contributions are welcome! If you find a bug or have a feature request, please open an issue on GitHub.

---

## License 📄

This project is licensed under the MIT License. See the `LICENSE` file for details.
