# RECONZ

**Automated, Scope-Aware Reconnaissance & DAST Pipeline for Bug Bounty and Pentesting.**

RECONZ is a unified pipeline that chains together industry-standard tools to automate sub-domain discovery, port scanning, URL harvesting, parameter fuzzing, and vulnerability scanning. It is designed to be completely hands-off, rate-limited for WAF safety, and context-aware for both authenticated and unauthenticated testing.

*Reference and special thanks to my mentor, [Rootbakar](https://github.com/rootbakar)! Check out their work: https://github.com/rootbakar/rb_recon_v3*

## ✨ Key Features
* **Strict Scope Filtering:** Input `domain.com` for a wide sweep, or `domain.com/myapp` to strictly lock all crawlers and fuzzers to a specific path.
* **Authentication Safe:** Automatically detects if `header.txt` is present. If authenticated, it aggressively filters out dangerous state-changing endpoints (e.g., `/logout`, `/delete`) to prevent session drops and data destruction.
* **WAF Rate-Limiting:** Built-in rate limits for Nuclei and Dirsearch to prevent rapid IP bans from Cloudflare/Akamai.
* **Smart JS Scanning:** Automatically isolates `.js` files from the crawl and hunts for hardcoded AWS keys and API tokens.

## 🛠️ Prerequisites

Make sure the following tools are installed and accessible in your system's `$PATH`:

* [Subfinder](https://github.com/projectdiscovery/subfinder)
* [Naabu](https://github.com/projectdiscovery/naabu)
* [Httpx](https://github.com/projectdiscovery/httpx)
* [Nuclei](https://github.com/projectdiscovery/nuclei) (Make sure your templates are updated!)
* [Katana](https://github.com/projectdiscovery/katana)
* [Hakrawler](https://github.com/hakluke/hakrawler)
* [Gau](https://github.com/lc/gau)
* [Waybackurls](https://github.com/tomnomnom/waybackurls)
* [Urldedupe](https://github.com/ameenmaali/urldedupe)
* [Gf](https://github.com/tomnomnom/gf) (With `lfi`, `redirect`, `sqli-error`, etc. patterns configured)
* [Qsreplace](https://github.com/tomnomnom/qsreplace)
* [Anew](https://github.com/tomnomnom/anew)
* [Subzy](https://github.com/LukaSikic/subzy) (Optional, for Subdomain Takeovers)
* [ParamSpider](https://github.com/devanshbatham/ParamSpider) (Optional, for archived parameters)
* [Arjun](https://github.com/s0md3v/Arjun) (Optional, for hidden parameter discovery)
* [x8](https://github.com/shmilylty/x8) (Optional, for hidden parameter discovery)
* [SQLMap](https://github.com/sqlmapproject/sqlmap) (Optional, for automated SQLi)
* [Dalfox](https://github.com/hahwul/dalfox)
* [Dirsearch](https://github.com/maurosoria/dirsearch)

## 🚀 Usage

**1. Configure Environment Variables**
Copy the example environment file and edit it to suit your setup:
```bash
cp .env.example .env
```
Inside `.env`:
* `SAVE_DIR`: Define where to save the final result (default: `./results`).
* `NUCLEI_TEMPLATE_DIR`: Define where your nuclei-templates are located.
* `TELEGRAM_NOTIF`: Set to `true` to get a push notification with the results.
* `TELEGRAM_BOT_ID`: Your Telegram bot ID.
* `TELEGRAM_CHAT_ID`: Your Telegram chat ID.

**2. Setup Authentication (Optional)**
To run an authenticated scan, paste your session cookies or bearer tokens into a `header.txt` file in the same directory. RECONZ will automatically parse this and inject it safely into Katana, Hakrawler, Nuclei, Arjun, x8, Dalfox, SQLMap, and Dirsearch.
```text
Host: redacted.ltd
Cookie: SESSIONID=xxx
Authorization: Bearer eyJhb...
```

**3. Run the Pipeline**
Execute the script and follow the prompt. 
```bash
./init.sh
```
*Prompt:* `Enter target (e.g., example.com OR example.com/myapp1):`
* Inputting a root domain (`example.com`) triggers full subdomain enumeration and port scanning.
* Inputting a path (`example.com/app`) skips subdomains and strictly scopes all fuzzing to that specific directory.

## ⚙️ How It Works (The Pipeline)

RECONZ abandons the old "choose an option" menu in favor of a continuous, start-to-finish automated pipeline:

* **PHASE 1: Scope Definition & Live Hosts**
    * Determines if the target is a root domain or a specific path.
    * Runs `subfinder` -> `naabu` (top 100 ports) -> `httpx` to build a list of live targets.
* **PHASE 1.5: Subdomain Takeover (Subzy)**
    * Quickly scans all discovered subdomains to see if any are vulnerable to hostile takeovers.
* **PHASE 2: URL Harvesting & Scope Filtering**
    * Unleashes `katana`, `hakrawler`, `gau`, `waybackurls`, and `paramspider` on the live hosts.
    * Deduplicates the massive URL output natively.
    * *Safety Check:* Strips out dangerous endpoints (`logout`, `delete`, etc.) if auth headers are detected. Applies strict regex filtering if a specific path was targeted.
* **PHASE 3: Parameter Extraction**
    * Uses `gf` to find vulnerable parameter patterns (SSRF, LFI, SQLi, XSS) and preps them with `qsreplace` for fuzzing.
* **PHASE 3.5: JavaScript Secret Scanning**
    * Isolates `.js` files and uses Nuclei to hunt for exposed tokens and credentials.
* **PHASE 3.8 & 3.9: Hidden Parameter Discovery (Arjun & x8)**
    * Aggressively brute-forces live endpoints to uncover hidden/unlinked parameters (GET, POST, JSON, XML).
* **PHASE 4: Vulnerability Scanning (Nuclei)**
    * Runs general Nuclei templates (CVEs, Misconfigs, Exposed Panels) against live hosts.
    * Runs DAST Nuclei templates against the extracted parameters.
* **PHASE 4.5: Advanced XSS Fuzzing (Dalfox)**
    * Fuzzes the extracted parameters specifically for DOM/Reflected/Stored XSS vulnerabilities.
* **PHASE 4.8: Automated SQL Injection (SQLMap)**
    * Runs an aggressive SQLMap scan (`--level=3 --risk=3 --tamper=between`) against fuzzable URLs.
* **PHASE 5: Directory Fuzzing (Dirsearch)**
    * Brute-forces hidden directories and files, outputting clean plain-text results (ignoring 404s and 400s).
* **PHASE 6: Compiling Results**
    * Aggregates only the actionable vulnerabilities and live host files into a final report.
    * Sends the report via Telegram (if configured) and cleans up the temporary workspace.
```