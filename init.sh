#!/bin/bash

# Load environment variables from .env file
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Global Variables
HEADER_OPTIONS=""
HEADER_OPTIONS_HAKRAWLER=""
SAVE_DIR=${SAVE_DIR:-"./results"} # Default to ./results if not set in .env
NUCLEI_TEMPLATE_DIR=${NUCLEI_TEMPLATE_DIR:-"$HOME/nuclei-templates"}

# Rate Limits (To prevent WAF bans like Cloudflare)
RATE_LIMIT_NUCLEI=150
RATE_LIMIT_DIRSEARCH=100

# Load Headers
if [ -f "header.txt" ] && [ -s "header.txt" ]; then
  while IFS= read -r header; do
    HEADER_OPTIONS="$HEADER_OPTIONS -H \"$header\""
    HEADER_OPTIONS_HAKRAWLER="$HEADER_OPTIONS_HAKRAWLER -h \"$header\""
  done < "header.txt"
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

# Get Target
read -p "Enter target (e.g., example.com OR example.com/myapp1): " rawTarget

# Clean up input (remove http:// or https:// if accidentally pasted)
cleanTarget=$(echo "$rawTarget" | sed -e 's|^[^/]*//||' -e 's|/$||')
escapedUrl=$(echo "$cleanTarget" | sed 's|/|_|g')

TMP_DIR="./tmp-$escapedUrl"
mkdir -p "$TMP_DIR"
mkdir -p "$SAVE_DIR/$escapedUrl"

echo -e "\n================================================="
echo " PHASE 1: Scope Definition & Live Hosts (with Naabu)"
echo "================================================="

# Check if the target includes a path (a slash)
if [[ "$cleanTarget" == *"/"* ]]; then
    echo "[*] Specific path detected ($cleanTarget)."
    echo "[*] Skipping Subfinder and Naabu to remain strictly in scope."
    
    rootDomain=$(echo "$cleanTarget" | awk -F/ '{print $1}')
    
    # Probe to see if the specific app is alive
    echo "$cleanTarget" | httpx -silent $HEADER_OPTIONS > "$TMP_DIR/live_hosts.txt"
    
    IS_PATH_TARGET=true
else
    echo "[*] Root domain detected. Running Subfinder & Naabu Port Scan..."
    # subfinder -> naabu (top 100 ports) -> httpx
    subfinder -d "$cleanTarget" -all -silent | naabu -silent -top-ports 100 | httpx -silent $HEADER_OPTIONS > "$TMP_DIR/live_hosts.txt"
    
    rootDomain="$cleanTarget"
    IS_PATH_TARGET=false
fi

if [ ! -s "$TMP_DIR/live_hosts.txt" ]; then
    echo "[-] No live hosts found. Exiting."
    rm -rf "$TMP_DIR"
    exit 1
fi
echo "[+] Found $(wc -l < "$TMP_DIR/live_hosts.txt") live services."

echo -e "\n================================================="
echo " PHASE 2: URL Harvesting & Strict Scope Filtering"
echo "================================================="

SAFE_REGEX=$(echo "$cleanTarget" | sed 's/\./\\./g')
STRICT_MATCH="^https?://${SAFE_REGEX}(/|\?|$)"

if [ "$IS_PATH_TARGET" = true ]; then
    echo "[*] STRICT SCOPE ENABLED: Locking all tools to $cleanTarget"
    TARGET_URL="https://$cleanTarget"
    
    echo "[*] Running Katana..."
    echo "$TARGET_URL" | katana -silent $HEADER_OPTIONS | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_katana.txt"

    echo "[*] Running Hakrawler..."
    echo "$TARGET_URL" | hakrawler $HEADER_OPTIONS_HAKRAWLER -subs -u | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_hakrawler.txt"

    echo "[*] Running GAU & Waybackurls..."
    echo "$rootDomain" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4 | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_gau.txt"
    echo "$rootDomain" | waybackurls | grep -E "$STRICT_MATCH" > "$TMP_DIR/urls_wayback.txt"

else
    echo "[*] ROOT DOMAIN SCOPE: Crawling all discovered subdomains..."
    
    echo "[*] Running Katana..."
    cat "$TMP_DIR/live_hosts.txt" | katana -silent $HEADER_OPTIONS > "$TMP_DIR/urls_katana.txt"

    echo "[*] Running Hakrawler..."
    cat "$TMP_DIR/live_hosts.txt" | hakrawler $HEADER_OPTIONS_HAKRAWLER -subs -u > "$TMP_DIR/urls_hakrawler.txt"

    echo "[*] Running GAU & Waybackurls..."
    cat "$TMP_DIR/live_hosts.txt" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4 > "$TMP_DIR/urls_gau.txt"
    cat "$TMP_DIR/live_hosts.txt" | waybackurls > "$TMP_DIR/urls_wayback.txt"
fi

echo "[*] Aggregating URLs..."
cat "$TMP_DIR"/urls_*.txt | urldedupe -s > "$TMP_DIR/raw_all_urls.txt"

# Conditionally strip out dangerous state-changing or logout URLs
if [ -n "$HEADER_OPTIONS" ]; then
    echo "[*] Authentication headers detected! Removing dangerous endpoints (logout, delete, etc.)..."
    cat "$TMP_DIR/raw_all_urls.txt" | grep -viE "logout|signout|logoff|delete|remove|destroy|revoke|kill|update" > "$TMP_DIR/all_urls.txt"
else
    echo "[*] Unauthenticated scan. Keeping all endpoints to test for Broken Access Control..."
    mv "$TMP_DIR/raw_all_urls.txt" "$TMP_DIR/all_urls.txt"
fi

echo "[+] Total unique, safe, strictly in-scope URLs collected: $(wc -l < "$TMP_DIR/all_urls.txt")"

echo -e "\n================================================="
echo " PHASE 3: Parameter Extraction & Fuzz Prep"
echo "================================================="
cat "$TMP_DIR/all_urls.txt" | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | anew "$TMP_DIR/fuzzable_urls.txt"
echo "[+] Found $(wc -l < "$TMP_DIR/fuzzable_urls.txt") parameters to fuzz."

echo -e "\n================================================="
echo " PHASE 3.5: JavaScript Secret Scanning"
echo "================================================="
cat "$TMP_DIR/all_urls.txt" | grep -iE "\.js(\?|$)" > "$TMP_DIR/js_urls.txt"

if [ -s "$TMP_DIR/js_urls.txt" ]; then
    echo "[+] Found $(wc -l < "$TMP_DIR/js_urls.txt") JS files. Scanning for hardcoded secrets..."
    nuclei -l "$TMP_DIR/js_urls.txt" $HEADER_OPTIONS -tags exposure,token -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_secrets.txt"
else
    echo "[-] No JavaScript files found."
fi

echo -e "\n================================================="
echo " PHASE 4: Vulnerability Scanning (Nuclei)"
echo "================================================="

echo "[*] Running General Nuclei Scan (CVEs, Misconfigs, Exposed Panels, WordPress)..."
nuclei -l "$TMP_DIR/live_hosts.txt" $HEADER_OPTIONS -tags cve,misconfig,panel,wordpress -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_general.txt"

echo "[*] Running DAST Nuclei Scan on parameters..."
if [ -s "$TMP_DIR/fuzzable_urls.txt" ]; then
    cat "$TMP_DIR/fuzzable_urls.txt" | nuclei $HEADER_OPTIONS -tags dast -dast -rl $RATE_LIMIT_NUCLEI -o "$TMP_DIR/nuclei_dast.txt"
else
    echo "[-] No fuzzable parameters found, skipping DAST."
fi

echo -e "\n================================================="
echo " PHASE 4.5: Advanced XSS Fuzzing (Dalfox)"
echo "================================================="
if [ -s "$TMP_DIR/fuzzable_urls.txt" ]; then
    echo "[*] Running Dalfox on extracted parameters..."
    
    # --skip-bav disables base-analyzing volume (makes it faster)
    # --skip-mining prevents it from crawling, sticking strictly to our URL list
    DALFOX_CMD="dalfox file \"$TMP_DIR/fuzzable_urls.txt\" -o \"$TMP_DIR/dalfox_results.txt\" --skip-bav --skip-mining"
    
    # Inject headers if they exist
    if [ -n "$HEADER_OPTIONS" ]; then
        echo "[!] WARNING: Running Dalfox Authenticated. Watch out for Stored XSS pollution!"
        DALFOX_CMD="$DALFOX_CMD $HEADER_OPTIONS"
    fi
    
    eval "$DALFOX_CMD"
    echo "[+] Dalfox completed."
else
    echo "[-] No fuzzable parameters found, skipping Dalfox."
fi

echo -e "\n================================================="
echo " PHASE 5: Directory Fuzzing (Dirsearch)"
echo "================================================="
echo "[*] Running Dirsearch (Rate limited to $RATE_LIMIT_DIRSEARCH req/s)..."

# Build base dirsearch command with plain text formatting for clean URL output
DIRSEARCH_CMD="dirsearch -u \"https://$cleanTarget\" -e php,html,js,json,bak,txt,zip,tar.gz -x 400,404,500 -o \"$TMP_DIR/dirsearch_results.txt\" --max-rate $RATE_LIMIT_DIRSEARCH"

# If header.txt exists, inject it natively! No sudo needed.
if [ -f "header.txt" ] && [ -s "header.txt" ]; then
    echo "[+] Injecting authentication headers into Dirsearch..."
    DIRSEARCH_CMD="$DIRSEARCH_CMD --headers-file=header.txt"
fi

eval "$DIRSEARCH_CMD"
echo "[+] Dirsearch completed."

echo -e "\n================================================="
echo " PHASE 6: Compiling Results & Cleanup"
echo "================================================="
# Only compile the actual findings, not the massive raw URL lists
cat "$TMP_DIR/live_hosts.txt" "$TMP_DIR"/nuclei_*.txt "$TMP_DIR/dalfox_results.txt" "$TMP_DIR/dirsearch_results.txt" 2>/dev/null | anew "$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt"

if [ "$TELEGRAM_NOTIF" = true ]; then
  echo "[*] Sending results to Telegram..."
  curl -s -F chat_id="$TELEGRAM_CHAT_ID" \
       -F document=@"$SAVE_DIR/$escapedUrl/final-recon-$escapedUrl.txt" \
       -F caption="Recon & DAST completed for $cleanTarget" \
       "https://api.telegram.org/bot$TELEGRAM_BOT_ID/sendDocument" > /dev/null
  echo "[+] Telegram notification sent!"
fi

echo "[*] Cleaning up temporary files..."
rm -rf "$TMP_DIR"

echo "[+] Pipeline Complete! Results saved to $SAVE_DIR/$escapedUrl/"