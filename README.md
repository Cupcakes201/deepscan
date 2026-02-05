# DeepScan Pro v4.2

**The Final Form of Automated Web Enumeration**

DeepScan Pro is a powerful, educational-grade web enumeration wrapper designed to streamline the usage of popular tools like `feroxbuster`, `ffuf`, and `dirb`. It adds advanced rate-limiting, WAF evasion techniques, noise filtering, and critical vulnerability detection.

## 🚀 Key Features

*   **Multi-Engine Support**: Seamlessly switch between `feroxbuster` (default), `ffuf`, and `dirb`.
*   **WAF Evasion**: 
    *   Automated User-Agent rotation.
    *   Proxy rotation.
    *   Jitter (randomized delays) to bypass rate limits.
    *   WAF evasion headers (X-Forwarded-For, etc.).
*   **Intelligent Noise Filtering**: Removes false positives based on response size, baseline comparison (404 detection), and similarity thresholds.
*   **Critical Detection**: Automatically flags potential LFI, SQLi, PHP errors, and exposed backup files during the scan.
*   **Reporting**: Includes a separate module (`repmak.sh`) to generate beautiful HTML and JSON reports.

## 📋 Requirements

Ensure the following tools are installed in your path:

*   `curl`
*   `parallel`
*   `bc` (Basic Calculator)
*   `md5sum` (Coreutils)
*   `shuf` (Coreutils)
*   **Engine**: At least one of `feroxbuster`, `ffuf`, or `dirb`.
*   `jq` (Highly recommended for JSON report generation)

## 🛠️ Installation

1.  Clone or download this repository.
2.  Make the scripts executable:

    ```bash
    chmod +x deepscan4.2.sh repmak.sh waf_module.sh
    ```

3.  (Optional) Configure your WAF evasion lists in the `config/` directory (created on first run).

## 📖 Usage

### Running a Scan

**Basic Syntax:**
```bash
./deepscan4.2.sh -t <target> -w <wordlist> [options]
```

**Common Examples:**

*   **Fast Optimization (Auto-Tune)**:
    ```bash
    ./deepscan4.2.sh -t http://example.com -w wordlist.txt --auto-tune
    ```

*   **Stealth / WAF Evasion (1 request per 5s + jitter)**:
    ```bash
    ./deepscan4.2.sh -t http://example.com -w wordlist.txt -T 1 -d 5000
    ```

*   **Recursive Scan (Depth 3, specific extensions)**:
    ```bash
    ./deepscan4.2.sh -t http://example.com -w wordlist.txt -r --depth 3 -x php,html,txt
    ```

**Options:**

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-t, --target` | Target URL | Required |
| `-w, --wordlist` | Path to wordlist | Required |
| `-e, --engine` | Select engine (`dirb`, `feroxbuster`, `ffuf`) | `feroxbuster` |
| `-d, --delay` | Delay between requests in ms (adds jitter) | `0` |
| `-T, --threads` | Number of concurrent threads | Auto |
| `-r, --recursive` | Enable directory recursion | `false` |
| `-x, --extensions` | File extensions to append (comma-separated) | None |
| `--fast` | Fast mode (skips deep analysis) | `false` |
| `-F, --no-filter` | Disable noise filtering | Enabled |

### Generating Reports

After a scan completes, use `repmak.sh` to generate user-friendly reports from the results directory.

**Syntax:**
```bash
./repmak.sh <scan_directory> [options]
```

**Examples:**

*   **Generate both HTML and JSON reports (recommended):**
    ```bash
    ./repmak.sh scan_feroxbuster_1715629402 --both
    ```

*   **Generate HTML only:**
    ```bash
    ./repmak.sh scan_feroxbuster_1715629402 --html
    ```

The HTML report provides an interactive dashboard with search, filtering, and severity highlighting.

## ⚙️ Configuration (WAF Module)

The `waf_module.sh` script manages evasion resources. Upon the first run, it creates a `config/` directory where you can customize:

*   `config/user_agents.txt`: List of User-Agents to rotate.
*   `config/proxies.txt`: List of HTTP proxies (e.g., `http://127.0.0.1:8080`).
*   `config/headers.txt`: Custom headers (e.g., `Referer: https://google.com`).

## ⚠️ Disclaimer

This tool is for **EDUCATIONAL PURPOSES** and **AUTHORIZED SECURITY TESTING ONLY**. 
Do not use this tool on targets you do not own or do not have explicit permission to test. The authors are not responsible for any misuse or damage caused by this software.
