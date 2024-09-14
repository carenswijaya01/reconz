#!/bin/bash

# Load environment variables from .env file
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Global Variables
targetUrl=""
total_runs=17

# Show Intro
intro() {
  echo "░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ "
  echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ "
  echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░    ░▒▓██▓▒░  "
  echo "░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓██▓▒░    "
  echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██▓▒░      "
  echo "░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        "
  echo "░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ "
  echo ""
  echo "Prerequisite: See README.md!\n"
  echo "SAVE_DIR            : $SAVE_DIR"
  echo "NUCLEI_TEMPLATE_DIR : $NUCLEI_TEMPLATE_DIR"
}

# Input Target URL
getUrl() {
  echo ""
  echo "===== DEFINE TARGET URL ====="
  read -p "Enter target url (without http/https): " targetUrl
  echo ""

  mkdir ./tmp-$targetUrl
}

# Execution
run1() {
  echo "\nNuclei template: /http/vulnerabilities/wordpress"
  echo "$targetUrl" | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/http/vulnerabilities/wordpress" -o "./tmp-$targetUrl/wpscann-$targetUrl-nuclei.txt"
}

run2() {
  echo "\nNuclei template: /dast/vulnerabilities (with gau, gf, qsreplace)"
  echo "$targetUrl" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4 | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result1-$targetUrl.txt"
}

run3() {
  echo "\nNuclei template: /dast/vulnerabilities (with gau, qsreplace)"
  echo "$targetUrl" | gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff,woff2,eot,ttf,otf,mp4 | urldedupe -s | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result2-$targetUrl.txt"
}

run4() {
  echo "\nNuclei template: /dast/vulnerabilities (with waybackurls, gf, qsreplace)"
  echo "$targetUrl" | waybackurls | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result3-$targetUrl.txt"
}

run5() {
  echo "\nNuclei template: /dast/vulnerabilities (with waybackurls, qsreplace)"
  echo "$targetUrl" | waybackurls | urldedupe -s | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result4-$targetUrl.txt"
}

run6() {
  echo "\nNuclei template: /dast/vulnerabilities (with gauplus, gf, qsreplace)"
  echo "$targetUrl" | gauplus | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result5-$targetUrl.txt"
}

run7() {
  echo "\nNuclei template: /dast/vulnerabilities (with gauplus, qsreplace)"
  echo "$targetUrl" | gauplus | urldedupe -s | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result6-$targetUrl.txt"
}

run8() {
  echo "\nNuclei template: /dast/vulnerabilities (with paramspider and gf)"
  paramspider -d "$targetUrl"
  cat "./results/$targetUrl.txt" | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result7-$targetUrl.txt"
}

run9() {
  echo "\nNuclei template: /dast/vulnerabilities (with paramspider)"
  paramspider -d "$targetUrl"
  cat "./results/$targetUrl.txt" | urldedupe -s | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result8-$targetUrl.txt"
}

run10() {
  echo "\nNuclei template: /dast/vulnerabilities (with katana, gf, qsreplace)"
  echo "$targetUrl" | httpx -silent | katana -silent | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result9-$targetUrl.txt"
}

run11() {
  echo "\nNuclei template: /dast/vulnerabilities (with katana, qsreplace)"
  echo "$targetUrl" | httpx -silent | katana -silent | urldedupe -s | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result10-$targetUrl.txt"
}

run12() {
  echo "\nNuclei template: /dast/vulnerabilities (with hakrawler, gf, qsreplace)"
  echo "$targetUrl" | httpx -silent | hakrawler -subs -u | urldedupe -s | gf lfi redirect sqli-error sqli ssrf ssti xss xxe | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result11-$targetUrl.txt"
}

run13() {
  echo "\nNuclei template: /dast/vulnerabilities (with hakrawler, qsreplace)"
  echo "$targetUrl" | httpx -silent | hakrawler -subs -u | urldedupe -s | qsreplace FUZZ | grep FUZZ | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/dast/vulnerabilities" -dast -o "./tmp-$targetUrl/result12-$targetUrl.txt"
}

run14() {
  echo "\nNuclei template: /http/exposures"
  echo "$targetUrl" | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/http/exposures" -o "./tmp-$targetUrl/exposures-$targetUrl.txt"
}

run15() {
  echo "\nNuclei template: /http/exposed-panels"
  echo "$targetUrl" | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/http/exposed-panels" -o "./tmp-$targetUrl/exposed-panels-$targetUrl.txt"
}

run16() {
  echo "\nNuclei template: /http/default-logins"
  echo "$targetUrl" | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/http/default-logins/" -o "./tmp-$targetUrl/default-logins-1-$targetUrl.txt"
}

run17() {
  echo "\nNuclei template: /default-logins"
  echo "$targetUrl" | nuclei -silent -t "$NUCLEI_TEMPLATE_DIR/default-logins" -o "./tmp-$targetUrl/default-logins-2-$targetUrl.txt"
}

makeResult () {
  echo ""
  echo "===== GENERATING RESULT ====="
  mkdir "$SAVE_DIR/$targetUrl"
  cd ./tmp-$targetUrl
  cat *.txt | anew final-result-$targetUrl.txt

  if [ "$TELEGRAM_NOTIF" = true ]; then
    sendTelegram
  fi

  mv final-result-$targetUrl.txt "$SAVE_DIR/$targetUrl"
  cd ..
}

removeTmp() {
  echo ""
  echo "===== REMOVING TMP FILES ====="
  rm -rf ./results/$targetUrl.txt
  rm -rf ./tmp-$targetUrl
  echo "Done!"
}

showMenu() {
  echo ""
  echo "===== MAIN MENU ====="
  echo "Target: $targetUrl"
  echo "Choose an option:"
  for i in $(seq 1 $total_runs); do
    # Print options in columns
    printf "%-15s" "$i) Run $i"

    # New line every 3 options
    if [ $(expr $i % 3) -eq 0 ]; then
      echo ""
    fi
  done

  if [ $(expr $total_runs % 3) -ne 0 ]; then
    echo ""
  fi

  if [ "$TELEGRAM_NOTIF" = true ]; then
    echo "$((total_runs + 1))) Make final result (anew) and send to Telegram"
  else
    echo "$((total_runs + 1))) Make final result (anew)"
  fi
  echo "$((total_runs + 2))) Run all (1-$total_runs and make final result)"
  echo "$((total_runs + 3))) Remove temporary files"
  echo "$((total_runs + 4))) Exit"
}

sendTelegram() {
  echo ""
  echo "===== SEND TO TELEGRAM BOT ====="

  if curl -F chat_id=$TELEGRAM_CHAT_ID \
     -F document=@final-result-$targetUrl.txt \
     -F caption="Recon result for $targetUrl" \
     https://api.telegram.org/bot$TELEGRAM_BOT_ID/sendDocument \
     > /dev/null 2>&1; then
     echo "Sent!"
  else
     echo "Failed to send."
  fi
}

# Main script flow
intro
getUrl

while true; do
  showMenu
  echo -n "Enter your choice: "
  read choice

  if [ "$choice" -ge 1 ] && [ "$choice" -le "$total_runs" ]; then
    eval "run$choice"
  else
    case $choice in
      $((total_runs + 1))) makeResult ;;
      $((total_runs + 2)))
        for i in $(seq 1 $total_runs); do
          eval "run$i"
        done
        makeResult
        ;;
      $((total_runs + 3))) removeTmp ;;
      $((total_runs + 4))) echo "Exiting..."; exit 0 ;;
      *) echo "Invalid option. Please try again." ;;
    esac
  fi
done
