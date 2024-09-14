# RECONZ

Automate Recon Tools for Scanning Vulnerabilities on a Single Target

Reference from my mentor, thanks to [Rootbakar](https://github.com/rootbakar)!
https://github.com/rootbakar/rb_recon_v3

## Prerequisites

Nuclei: https://github.com/projectdiscovery/nuclei

Gau: https://github.com/lc/gau

Urldedupe: https://github.com/ameenmaali/urldedupe

Gf: https://github.com/tomnomnom/gf

Qsreplace: https://github.com/tomnomnom/qsreplace

Waybackurls: https://github.com/tomnomnom/waybackurls

Gauplus: https://github.com/bp0lr/gauplus

ParamSpider: https://github.com/devanshbatham/ParamSpider

Httpx: https://github.com/projectdiscovery/httpx

Katana: https://github.com/projectdiscovery/katana

Hakrawler: https://github.com/hakluke/hakrawler

Anew: https://github.com/tomnomnom/anew

## Usage

1. Copy and paste `.env.example` into `.env`.
2. Configure the `.env` file.

   `SAVE_DIR` = define where to save the final result.

   `NUCLEI_TEMPLATE_DIR` = define where nuclei-templates located at.

3. Run the following command:

   ```
   sh ./init.sh
   ```

4. Wait for the result. The result will be located in your `SAVE_DIR`.

## Command Description

1 = Nuclei template: /http/vulnerabilities/wordpress

2 = Nuclei template: /dast/vulnerabilities (with gau, gf, qsreplace)

3 = Nuclei template: /dast/vulnerabilities (with gau, qsreplace)

4 = Nuclei template: /dast/vulnerabilities (with waybackurls, gf, qsreplace)

5 = Nuclei template: /dast/vulnerabilities (with waybackurls, qsreplace)

6 = Nuclei template: /dast/vulnerabilities (with gauplus, gf, qsreplace)

7 = Nuclei template: /dast/vulnerabilities (with gauplus, qsreplace)

8 = Nuclei template: /dast/vulnerabilities (with paramspider and gf)

9 = Nuclei template: /dast/vulnerabilities (with paramspider)

10 = Nuclei template: /dast/vulnerabilities (with katana, gf, qsreplace)

11 = Nuclei template: /dast/vulnerabilities (with katana, qsreplace)

12 = Nuclei template: /dast/vulnerabilities (with hakrawler, gf, qsreplace)

13 = Nuclei template: /dast/vulnerabilities (with hakrawler, qsreplace)

14 = Nuclei template: /http/exposures

15 = Nuclei template: /http/exposed-panels

16 = Nuclei template: /http/default-logins

17 = Nuclei template: /default-logins
