#!/bin/bash

# Load environment variables from .env file
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Global Variables
SAVE_DIR=${SAVE_DIR:-"./results"} # Default to ./results if not set in .env
NUCLEI_TEMPLATE_DIR=${NUCLEI_TEMPLATE_DIR:-"$HOME/nuclei-templates"}

# Rate Limits (To prevent WAF bans like Cloudflare)
RATE_LIMIT_NUCLEI=0
RATE_LIMIT_DIRSEARCH=0

# Phase Timing Helper
PHASE_START_TIME=0
phase_start() {
    PHASE_START_TIME=$(date +%s)
    echo -e "\n================================================="
    echo " $1"
    echo "================================================="
}

phase_end() {
    local elapsed=$(( $(date +%s) - PHASE_START_TIME ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    if [ $mins -gt 0 ]; then
        echo "[⏱] Phase completed in ${mins}m ${secs}s"
    else
        echo "[⏱] Phase completed in ${secs}s"
    fi
}

# Trap handler: preserve tmp files for resume on Ctrl+C or crash
cleanup() {
    echo -e "\n[!] Interrupted! Cleaning up child processes..."
    kill 0 2>/dev/null
    if [ -n "${TMP_DIR:-}" ]; then
        echo "[*] Temporary files preserved in $TMP_DIR for resume."
    fi
    exit 130
}
trap cleanup INT TERM

# Load Headers (Dynamic Function)
load_headers() {
    HEADER_ARGS=()
    HAKRAWLER_HEADER_ARGS=()
    if [ -f "header.txt" ] && [ -s "header.txt" ]; then
        while IFS= read -r header || [ -n "$header" ]; do
            header=$(echo "$header" | tr -d '\r' | xargs) # Strip \r and leading/trailing whitespace
            [ -z "$header" ] && continue
            HEADER_ARGS+=("-H" "$header")
            HAKRAWLER_HEADER_ARGS+=("-h" "$header")
        done < "header.txt"
    fi
}

# Check Auth Status (Failsafe) - skippable with --no-pause
check_auth_status() {
    if [ "$SKIP_AUTH_PAUSE" = true ]; then
        return
    fi
    if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
        echo -e "\n[*] PAUSE: We are about to start a heavy fuzzing phase."
        echo "[*] If your session cookie might expire soon, this is your chance to update it."
        echo "    -> Please open header.txt, paste your fresh session cookie, and save it."
        read -p "    -> Press [Enter] when you are ready to continue (or to proceed with current headers)..."
        
        # Reload the (potentially) newly pasted headers
        load_headers
        echo "[+] Headers loaded! Resuming scan..."
    fi
}

# Initial load
load_headers
if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
    echo "[+] Loaded headers from header.txt"
else
    echo "[-] No header.txt found or empty, proceeding without headers..."
fi

# Show Intro
echo "  _ \   __|   __|   _ \    \ | __  / "
echo "    /  _|   (     (   | .  |    /  "
echo " _|_\ ___| \___| \___/ _|\_| ____| "
echo "                                   "
echo "Automated Recon & DAST Pipeline"
echo "-----------------------------------"

# Check for required tools
check_tool() {
  if ! command -v $1 &> /dev/null; then
    echo "[-] Warning: $1 is not installed or not in PATH."
    return 1
  fi
  return 0
}

MISSING_CRITICAL=false
echo "[*] Checking critical tools..."
for tool in httpx nuclei katana hakrawler gau waybackurls gf qsreplace urldedupe anew subfinder naabu; do
    if ! check_tool $tool; then
        MISSING_CRITICAL=true
    fi
done
if [ "$MISSING_CRITICAL" = true ]; then
    echo "[!] WARNING: Some critical tools are missing. The pipeline may fail or skip phases."
fi

echo "[*] Checking optional elite tools..."
for tool in subzy x8 sqlmap paramspider assetfinder feroxbuster ffuf dalfox; do
  check_tool $tool
done


# Parse Command Line Arguments
rawTarget=""
SQLMAP_DBMS=""
INTERACTIVE=true
SKIP_DIRSCAN=false
SKIP_AUTH_PAUSE=false

if [ "$#" -gt 0 ]; then
    INTERACTIVE=false
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --url|-u) rawTarget="$2"; shift ;;
            --dbms|-d) SQLMAP_DBMS="$2"; shift ;;
            --skip-dir) SKIP_DIRSCAN=true ;;
            --no-pause) SKIP_AUTH_PAUSE=true ;;
            --help|-h) 
                echo "Usage: $0 --url <target> [--dbms <dbms_list>] [--skip-dir] [--no-pause]"
                echo "Example: $0 --url https://example.com --dbms MySQL --skip-dir --no-pause"
                echo ""
                echo "Options:"
                echo "  --url, -u       Target URL or domain"
                echo "  --dbms, -d      SQLMap DBMS hint (e.g., MySQL, PostgreSQL)"
                echo "  --skip-dir      Skip Phase 5 (directory fuzzing)"
                echo "  --no-pause      Skip header-refresh pauses between phases"
                echo "  --help, -h      Show this help message"
                exit 0
                ;;
            *) echo "[-] Unknown parameter passed: $1"; exit 1 ;;
        esac
        shift
    done
fi

# Fallback to interactive prompts if target was not provided via arguments
if [ -z "$rawTarget" ]; then
    read -p "Enter target (e.g., example.com OR https://example.com/myapp1): " rawTarget
fi

# Ask interactively if they want to run the long directory scan
if [ "$INTERACTIVE" = true ]; then
    echo ""
    read -p "Run deep directory fuzzing (Phase 5)? This can take a long time. (y/N): " run_dir
    if [[ ! "$run_dir" =~ ^[Yy]$ ]]; then
        SKIP_DIRSCAN=true
    fi
fi

# Clean up input (remove http:// or https:// if accidentally pasted)
cleanTarget=$(echo "$rawTarget" | sed -e 's|^[^/]*//||' -e 's|/$||')
escapedUrl=$(echo "$cleanTarget" | sed 's|/|_|g')

if [ -z "$cleanTarget" ]; then
    echo "[-] Error: Target URL is required."
    exit 1
fi

# Get SQLMap DBMS Preference interactively ONLY if no CLI arguments were passed
if [ "$INTERACTIVE" = true ] && [ -z "$SQLMAP_DBMS" ]; then
    echo ""
    echo "Optional: Specify a single target Database Management System for SQLMap to speed it up."
    echo "Examples: MySQL, PostgreSQL, Oracle, Microsoft SQL Server"
    read -p "Enter DBMS (or press Enter to let SQLMap auto-detect): " SQLMAP_DBMS
fi

TMP_DIR="./tmp-$escapedUrl"
mkdir -p "$TMP_DIR"
mkdir -p "$SAVE_DIR/$escapedUrl"

PIPELINE_START=$(date +%s)

phase_start "PHASE 1: Scope Definition & Live Hosts (with Naabu)"

# Check if the target includes a path (a slash)
if [[ "$cleanTarget" == *"/"* ]]; then
    echo "[*] Specific path detected ($cleanTarget)."
    echo "[*] Skipping Subfinder and Naabu to remain strictly in scope."
    
    rootDomain=$(echo "$cleanTarget" | awk -F/ '{print $1}')
    
    # Probe to see if the specific app is alive
    echo "$cleanTarget" | httpx -silent "${HEADER_ARGS[@]}" -sc -title -tech-detect -ip > "$TMP_DIR/live_hosts_info.txt"
    
    IS_PATH_TARGET=true
else
    echo "[*] Root/Sub-domain detected. Running Subfinder & Naabu Port Scan..."
    
    # Ensure the target itself is always in the list, even if subfinder finds nothing
    echo "$cleanTarget" > "$TMP_DIR/subs.txt"
    
    # Notice the >> so it APPENDS without deleting the line above!
    subfinder -d "$cleanTarget" -all -silent >> "$TMP_DIR/subs.txt" 2>/dev/null
    
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only "$cleanTarget" >> "$TMP_DIR/subs.txt" 2>/dev/null
    fi
    
    # Sort unique subdomains -> naabu (top 100 ports) -> httpx
    sort -u "$TMP_DIR/subs.txt" | naabu -silent -top-ports 100 | httpx -silent "${HEADER_ARGS[@]}" -sc -title -tech-detect -ip > "$TMP_DIR/live_hosts_info.txt"
    
    if [ ! -s "$TMP_DIR/live_hosts_info.txt" ]; then
        echo "[-] No live hosts found on top 100 ports. Trying raw httpx..."
        echo "$cleanTarget" | httpx -silent "${HEADER_ARGS[@]}" -sc -title -tech-detect -ip > "$TMP_DIR/live_hosts_info.txt"
    fi

    rootDomain="$cleanTarget"
    IS_PATH_TARGET=false
fi

# Create a clean list of just URLs for tools to use without crashing
awk '{print $1}' "$TMP_DIR/live_hosts_info.txt" > "$TMP_DIR/live_hosts.txt"

if [ ! -s "$TMP_DIR/live_hosts.txt" ]; then
    echo "[-] No live hosts resolved by httpx. Forcing the target URL to continue..."
    # Fallback to standard HTTPS so tools like Dirsearch/Nuclei still attempt it
    echo "https://$cleanTarget" > "$TMP_DIR/live_hosts.txt"
    echo "https://$cleanTarget" > "$TMP_DIR/live_hosts_info.txt"
fi
echo "[+] Proceeding with $(wc -l < "$TMP_DIR/live_hosts.txt") live service(s)."
phase_end

phase_start "PHASE 1.5: Subdomain Takeover (Subzy)"
if command -v subzy &> /dev/null; then
    echo "[*] Checking for Subdomain Takeovers..."
    # Run on all subdomains found, even dead ones, as they are prime targets for takeover
    TARGET_LIST="$TMP_DIR/subs.txt"
    [ ! -f "$TARGET_LIST" ] && TARGET_LIST="$TMP_DIR/live_hosts.txt"
    subzy run --targets "$TARGET_LIST" --hide_fails > "$TMP_DIR/subzy_results.txt" 2>/dev/null
    if [ -s "$TMP_DIR/subzy_results.txt" ]; then
        echo "[!] Potential Subdomain Takeovers found!"
    else
        echo "[-] No subdomain takeovers detected."
    fi
else
    echo "[-] subzy not installed, skipping..."
fi
phase_end

phase_start "PHASE 2: URL Harvesting & Strict Scope Filtering"

SAFE_REGEX=$(echo "$cleanTarget" | sed 's/\./\\./g')
STRICT_MATCH="^https?://${SAFE_REGEX}(/|\?|$)"

if [ "$IS_PATH_TARGET" = true ]; then
    echo "[*] STRICT SCOPE ENABLED: Locking all tools to $cleanTarget"
    TARGET_URL=$(head -n 1 "$TMP_DIR/live_hosts.txt")
    [ -z "$TARGET_URL" ] && TARGET_URL="https://$cleanTarget"
    
    echo "[*] Running Katana (Deep JS crawling enabled)..."
    echo "$TARGET_URL" | katana -jc "${HEADER_ARGS[@]}" | tee /dev/tty | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_katana.txt"

    echo "[*] Running Hakrawler..."
    echo "$TARGET_URL" | hakrawler "${HAKRAWLER_HEADER_ARGS[@]}" -subs -u | tee /dev/tty | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_hakrawler.txt"

    echo "[*] Running GAU & Waybackurls (Passive OSINT)..."
    # OSINT tools usually don't accept headers, but GAU allows passing them. Waybackurls does not.
    # We strip https:// so GAU and Waybackurls get the raw domain
    RAW_DOMAIN=$(echo "$TARGET_URL" | sed -E 's/^\s*.*:\/\///g' | awk -F/ '{print $1}')
    
    GAU_CMD="echo \"$RAW_DOMAIN\" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4"
    eval "$GAU_CMD" | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_gau.txt"
    
    echo "$RAW_DOMAIN" | waybackurls | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_wayback.txt"

else
    echo "[*] ROOT DOMAIN SCOPE: Crawling all discovered subdomains..."
    
    echo "[*] Running Katana (Deep JS crawling enabled)..."
    cat "$TMP_DIR/live_hosts.txt" | katana -jc "${HEADER_ARGS[@]}" | tee "$TMP_DIR/urls_katana.txt"

    echo "[*] Running Hakrawler..."
    cat "$TMP_DIR/live_hosts.txt" | hakrawler "${HAKRAWLER_HEADER_ARGS[@]}" -subs -u | tee "$TMP_DIR/urls_hakrawler.txt"

    echo "[*] Running GAU & Waybackurls (Passive OSINT)..."
    # Strip protocols to get just the domains for OSINT tools
    cat "$TMP_DIR/live_hosts.txt" | sed -E 's/^\s*.*:\/\///g' | awk -F/ '{print $1}' > "$TMP_DIR/raw_domains.txt"
    
    GAU_CMD="cat \"$TMP_DIR/raw_domains.txt\" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4"
    eval "$GAU_CMD" > "$TMP_DIR/urls_gau.txt"
    
    cat "$TMP_DIR/raw_domains.txt" | waybackurls > "$TMP_DIR/urls_wayback.txt"
fi

echo "[*] Running ParamSpider for archived parameters..."
if command -v paramspider &> /dev/null; then
    # ParamSpider expects a raw domain without protocol
    PS_DOMAIN=$(echo "$cleanTarget" | sed -E 's/^\s*.*:\/\///g' | awk -F/ '{print $1}')
    paramspider -d "$PS_DOMAIN"
    if [ -f "./results/$PS_DOMAIN.txt" ]; then
        cat "./results/$PS_DOMAIN.txt" > "$TMP_DIR/urls_paramspider.txt"
    fi
fi

echo "[*] Running targeted API discovery (ffuf)..."
if command -v ffuf &> /dev/null; then
    
    # Intelligently locate the SecLists API wordlist (Kali native paths first)
    API_WORDLIST=""
    if [ -f "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt" ]; then
        API_WORDLIST="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"
    elif [ -f "/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt" ]; then
        API_WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"
    elif [ -f "api_wordlist.txt" ]; then
        API_WORDLIST="api_wordlist.txt"
    else
        echo "[*] Local SecLists not found. Downloading fallback API wordlist..."
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints-res.txt -O api_wordlist.txt
        API_WORDLIST="api_wordlist.txt"
    fi
    
    # We use ffuf's multi-wordlist feature to test every live host against the API wordlist.
    # WAF SAFETY: We use process substitution <(...) to instantly strip dangerous words before ffuf runs.
    # BUG FIX: was referencing non-existent ffuf_hosts.txt, now uses live_hosts.txt
    FFUF_CMD="ffuf -w \"$TMP_DIR/live_hosts.txt:HOST\" -w <(grep -viE 'logout|signout|delete|remove|destroy|revoke|kill|update' \"$API_WORDLIST\"):FUZZ -u HOST/FUZZ -mc 200,201,301,302,401,403,405 -ac -rate $RATE_LIMIT_DIRSEARCH -of csv -o \"$TMP_DIR/ffuf_api.csv\" -t 50 -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\""
    
    # Inject authentication headers natively into ffuf
    if [ -f "header.txt" ] && [ -s "header.txt" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line=$(echo "$line" | tr -d '\r')
            if [ -n "$line" ]; then
                FFUF_CMD="$FFUF_CMD -H \"$line\""
            fi
        done < "header.txt"
    fi
    
    # Run ffuf and hide the noisy output from the terminal
    eval "$FFUF_CMD" > /dev/null 2>&1
    
    # Extract the discovered URLs from ffuf's CSV output (skipping the header row)
    if [ -f "$TMP_DIR/ffuf_api.csv" ]; then
        awk -F',' 'NR>1 {print $3}' "$TMP_DIR/ffuf_api.csv" > "$TMP_DIR/urls_ffuf.txt"
        echo "[+] ffuf found $(wc -l < "$TMP_DIR/urls_ffuf.txt") API endpoints using local SecLists!"
    fi
else
    echo "[-] ffuf not installed, skipping API discovery..."
fi

echo "[*] Aggregating URLs..."
cat "$TMP_DIR"/urls_*.txt 2>/dev/null | grep -E "$STRICT_MATCH" | urldedupe -s > "$TMP_DIR/raw_all_urls.txt"

# Conditionally strip out dangerous state-changing, logout URLs, and static directories
if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
    echo "[*] Authentication headers detected! Removing dangerous endpoints and static assets..."
    cat "$TMP_DIR/raw_all_urls.txt" | grep -viE "\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|pdf|ico|webp|mp4|zip|tar|gz)(\?|$)" | grep -viE "logout|signout|logoff|delete|remove|destroy|revoke|kill|update|/assets/" > "$TMP_DIR/all_urls.txt"
else
    echo "[*] Unauthenticated scan. Removing static assets..."
    # Add the /assets/ block here too!
    cat "$TMP_DIR/raw_all_urls.txt" | grep -viE "\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|pdf|ico|webp|mp4|zip|tar|gz)(\?|$)" | grep -vi "/assets/" > "$TMP_DIR/all_urls.txt"
fi

echo "[+] Total unique, safe, strictly in-scope URLs collected: $(wc -l < "$TMP_DIR/all_urls.txt")"

# Filter out dead OSINT links before they reach the fuzzers (prevents SQLMap/Dalfox time waste)
echo "[*] Verifying URLs are alive to prevent wasting SQLMap/Dalfox time..."
cat "$TMP_DIR/all_urls.txt" | httpx -silent "${HEADER_ARGS[@]}" -mc 200,201,301,302,307,401,403,405 -t 100 > "$TMP_DIR/alive_urls.txt"
mv "$TMP_DIR/alive_urls.txt" "$TMP_DIR/all_urls.txt"

echo "[+] Alive URLs passed to fuzzing phases: $(wc -l < "$TMP_DIR/all_urls.txt")"
phase_end

phase_start "PHASE 3: Parameter Extraction & Fuzz Prep"
cat "$TMP_DIR/all_urls.txt" | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | anew "$TMP_DIR/fuzzable_urls.txt"
echo "[+] Found $(wc -l < "$TMP_DIR/fuzzable_urls.txt") parameters to fuzz."
phase_end

phase_start "PHASE 3.5: JavaScript Secret Scanning"
# We extract JS URLs from the RAW list since we just stripped them from all_urls.txt
cat "$TMP_DIR/raw_all_urls.txt" | grep -iE "\.js(\?|$)" > "$TMP_DIR/js_urls.txt"

if [ -s "$TMP_DIR/js_urls.txt" ]; then
    echo "[+] Found $(wc -l < "$TMP_DIR/js_urls.txt") JS files. Scanning for hardcoded secrets..."
    nuclei -l "$TMP_DIR/js_urls.txt" "${HEADER_ARGS[@]}" -tags exposure,token -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_secrets.txt"
else
    echo "[-] No JavaScript files found."
fi
phase_end

# Phase 3.8 (Arjun) removed: Redundant with x8 (Phase 3.9) which is faster (Rust-based)
# and already has robust WAF-evasion. Running both doubled scan time and WAF ban risk.

phase_start "PHASE 3.9: Parameter Discovery (x8)"
load_headers
check_auth_status
if command -v x8 &> /dev/null; then
    echo "[*] Running x8 to double check for hidden parameters..."
    if [ ! -f "x8_wordlist.txt" ]; then
        echo "[-] x8 requires a wordlist. Please download a small/medium one to the current directory:"
        echo "    wget -q https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/small.txt -O x8_wordlist.txt"
        echo "[-] Skipping x8 for now until x8_wordlist.txt exists..."
    else
        # 1. WAF EVASION: Strip aggressive parameters that instantly trigger WAFs like FortiGate
        echo "[*] Sanitizing x8 wordlist to evade WAF signatures..."
        grep -viE "^(phpinfo|tftp|mkfile|exec|cmd|system|eval|shell|daemon|passwd|shadow|boot|config|mkdir|rownum|user_password|user_group|sleep|delay|benchmark|waitfor)$" x8_wordlist.txt > x8_clean.txt
        
        # 2. Run x8 with lower concurrency (-c 20 instead of 100) to avoid rate-based WAF blocks
        # We output to a raw file first so we can verify the findings
        X8_CMD="x8 -u \"$TMP_DIR/all_urls.txt\" -w x8_clean.txt -c 20 -X GET POST -O url -o \"$TMP_DIR/x8_raw.txt\""
        
        # Inject headers natively
        if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
            for header in "${HEADER_ARGS[@]}"; do
                X8_CMD="$X8_CMD \"$header\""
            done
        fi
    
        eval "$X8_CMD" || {
            echo "[-] x8 encountered an error or no parameters were found."
        }
        
        if [ -s "$TMP_DIR/x8_raw.txt" ]; then
            echo "[+] Filtering x8 false-positives caused by WAF blocks..."
            # 3. WAF BUFFER: Use httpx to check the URLs x8 found. 
            # If the WAF blocked it, it will return 403, 406, or 429. -fc filters those out!
            cat "$TMP_DIR/x8_raw.txt" | httpx -silent "${HEADER_ARGS[@]}" -fc 400,403,406,429 | qsreplace FUZZ | grep FUZZ | urldedupe -s >> "$TMP_DIR/fuzzable_urls.txt"
            
            echo "[+] x8 parameters verified and added to fuzzing queue."
        fi
    fi
else
    echo "[-] x8 not installed, skipping..."
fi
phase_end

phase_start "PHASE 4: Vulnerability Scanning (Nuclei)"
load_headers
check_auth_status

echo "[*] Running General Nuclei Scan (CVEs, Misconfigs, Exposed Panels, WordPress)..."
nuclei -l "$TMP_DIR/live_hosts.txt" "${HEADER_ARGS[@]}" -tags cve,misconfig,panel,wordpress -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_general.txt"

echo "[*] Running DAST Nuclei Scan on parameters..."
if [ -s "$TMP_DIR/fuzzable_urls.txt" ]; then
    # Strip =FUZZ so Nuclei recognizes the parameters normally (FUZZ is for ffuf/SQLMap, not Nuclei)
    cat "$TMP_DIR/fuzzable_urls.txt" | sed 's/=FUZZ/=/g' | nuclei "${HEADER_ARGS[@]}" -tags dast -dast -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_dast.txt"
else
    echo "[-] No fuzzable parameters found, skipping DAST."
fi
phase_end

phase_start "PHASE 4.5: Automated SQL Injection (SQLMap)"
load_headers
check_auth_status
if command -v sqlmap &> /dev/null; then
    if [ -s "$TMP_DIR/fuzzable_urls.txt" ]; then
        echo "[*] Running SQLMap on fuzzable URLs (Level 2, Risk 2)..."
        # Create a clean target list replacing FUZZ with empty to let sqlmap dynamically test
        cat "$TMP_DIR/fuzzable_urls.txt" | sed 's/FUZZ//g' | urldedupe -s > "$TMP_DIR/sqlmap_targets.txt"
        
        SQLMAP_CMD="sqlmap -m \"$TMP_DIR/sqlmap_targets.txt\" --batch --random-agent --retries=1 --level=2 --risk=2 --tamper=between --dbs -o --output-dir=\"$SAVE_DIR/$escapedUrl/sqlmap\""
        
        if [ -n "$SQLMAP_DBMS" ]; then
            SQLMAP_CMD="$SQLMAP_CMD --dbms=\"$SQLMAP_DBMS\""
        fi
        
        if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
            for i in $(seq 0 2 $((${#HEADER_ARGS[@]}-1))); do
                if [ "${HEADER_ARGS[$i]}" = "-H" ]; then
                    SQLMAP_CMD="$SQLMAP_CMD -H \"${HEADER_ARGS[$i+1]}\""
                fi
            done
        fi
        
        eval "$SQLMAP_CMD"
        echo "[+] SQLMap completed. Results (if any) are in $SAVE_DIR/$escapedUrl/sqlmap"
    else
        echo "[-] No fuzzable parameters found, skipping SQLMap."
    fi
else
    echo "[-] sqlmap not installed, skipping..."
fi
phase_end

phase_start "PHASE 4.8: Advanced XSS Fuzzing (Dalfox)"
load_headers
check_auth_status
if [ -s "$TMP_DIR/fuzzable_urls.txt" ]; then
    echo "[*] Running Dalfox on extracted parameters..."
    
    # --skip-bav disables base-analyzing volume (makes it faster)
    # --skip-mining-all prevents it from crawling/mining parameters, sticking strictly to our URL list
    DALFOX_CMD="dalfox file \"$TMP_DIR/fuzzable_urls.txt\" --skip-mining-all --skip-bav --silence --format plain -o \"$TMP_DIR/dalfox_xss.txt\""
    
    # Inject headers if they exist
    if [ ${#HEADER_ARGS[@]} -gt 0 ]; then
        echo "[!] WARNING: Running Dalfox Authenticated. Watch out for Stored XSS pollution!"
        for i in $(seq 0 2 $((${#HEADER_ARGS[@]}-1))); do
            if [ "${HEADER_ARGS[$i]}" = "-H" ]; then
                DALFOX_CMD="$DALFOX_CMD -H '${HEADER_ARGS[$i+1]}'"
            fi
        done
    fi
    
    eval "$DALFOX_CMD"
    echo "[+] Dalfox completed."
else
    echo "[-] No fuzzable parameters found, skipping Dalfox."
fi
phase_end

phase_start "PHASE 5: Directory & File Fuzzing (Feroxbuster)"

if [ "$SKIP_DIRSCAN" = true ]; then
    echo "[*] Skipping Directory Fuzzing as requested."
else
    load_headers
    check_auth_status
    echo "[*] Running Feroxbuster (Rate limited to $RATE_LIMIT_DIRSEARCH req/s)..."

    if command -v feroxbuster &> /dev/null; then
        # --depth 1: prevents endless recursive rabbit holes (each discovered dir would spawn a full new scan)
        # Trimmed extensions: removed html, js, json — Katana/Hakrawler already found the visible ones.
        # Only fuzz for high-value hidden files (backups, archives, config text, php logic).
        FEROX_CMD="feroxbuster --stdin --depth 1 -x php,bak,txt,zip,tar.gz -C 400,403,404,500 --rate-limit $RATE_LIMIT_DIRSEARCH --dont-scan '.*(logout|signout|logoff|delete|remove|destroy|revoke|kill|update|/assets/).*' -q -o \"$TMP_DIR/feroxbuster_results.txt\""

        if [ -f "header.txt" ] && [ -s "header.txt" ]; then
            echo "[+] Injecting authentication headers into Feroxbuster..."
            while IFS= read -r line || [ -n "$line" ]; do
                line=$(echo "$line" | tr -d '\r')
                if [ -n "$line" ]; then
                    FEROX_CMD="$FEROX_CMD -H \"$line\""
                fi
            done < "header.txt"
        fi

        eval "cat \"$TMP_DIR/live_hosts.txt\" | $FEROX_CMD"
        echo "[+] Feroxbuster completed."
    else
        echo "[-] feroxbuster not installed. Please install it to run this phase."
    fi
fi
phase_end

phase_start "PHASE 6: Compiling Results & Cleanup"
# Only compile the actual findings, not the massive raw URL lists
cat "$TMP_DIR/live_hosts_info.txt" "$TMP_DIR"/nuclei_*.txt "$TMP_DIR/subzy_results.txt" "$TMP_DIR/dalfox_xss.txt" "$TMP_DIR/feroxbuster_results.txt" 2>/dev/null | anew "$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt"

# Include SQLMap results summary if they exist
if [ -d "$SAVE_DIR/$escapedUrl/sqlmap" ]; then
    echo "--- SQLMap Results ---" >> "$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt"
    find "$SAVE_DIR/$escapedUrl/sqlmap" -name "log" -exec grep -l "is vulnerable" {} \; 2>/dev/null | while read logfile; do
        echo "[SQLi] $(dirname "$logfile" | xargs basename): VULNERABLE" >> "$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt"
    done
fi

if [ "${TELEGRAM_NOTIF:-false}" = true ]; then
  echo "[*] Sending results to Telegram..."
  curl -s -F chat_id="$TELEGRAM_CHAT_ID" \
       -F document=@"$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt" \
       -F caption="Recon & DAST completed for $cleanTarget" \
       "https://api.telegram.org/bot$TELEGRAM_BOT_ID/sendDocument" > /dev/null
  echo "[+] Telegram notification sent!"
fi

echo "[*] Cleaning up temporary files..."
rm -rf "$TMP_DIR"
phase_end

PIPELINE_END=$(date +%s)
TOTAL_ELAPSED=$(( PIPELINE_END - PIPELINE_START ))
TOTAL_MINS=$(( TOTAL_ELAPSED / 60 ))
TOTAL_SECS=$(( TOTAL_ELAPSED % 60 ))
echo -e "\n[+] Pipeline Complete! Total time: ${TOTAL_MINS}m ${TOTAL_SECS}s"
echo "[+] Results saved to $SAVE_DIR/$escapedUrl/"