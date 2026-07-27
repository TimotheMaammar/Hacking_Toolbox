# Subdomains.py

Subdomain enumeration (crt.sh, subfinder, assetfinder, findomain, gau passively
+ amass passively + DNS bruteforce/permutations via puredns/alterx),
results merged, deduped, sorted, and DNS-validated into a clean output file.
Meant to run in the background while you do something else.

## Usage

```bash
python3 Subdomains.py -d domains.txt -o dump_orange_com.txt
python3 Subdomains.py -d domains.txt -o dump.txt -t 3600
python3 Subdomains.py -d domains.txt -o dump.txt --skip-amass   # faster iteration while testing
```

- `-d domains.txt`: one domain (or `*.domain`) per line
- `-o`: base name for the output files (default `dump.txt`)
- `-t`: per-tool timeout in seconds (default 1800)
- `--skip-amass`: skip amass entirely

## Output

Two files get written:

- `dump.txt` -- everything found, deduped and sorted. Includes results from
  tools that are only format-validated (regex + domain suffix), never
  DNS-checked (crt.sh, subfinder, assetfinder, findomain, gau) -- so it can
  contain entries that look like a valid hostname but don't actually resolve
  (e.g. a parsing artifact from a malformed archived URL gau picked up).
- `dump_confirmed.txt` -- the subset of `dump.txt` that a final `puredns
  resolve` pass actually confirmed resolves. Use this one when accuracy
  matters more than raw breadth (e.g. submitting to something that penalizes
  invalid entries, like Recon Royale).

Both files are read back right after being written and the line count on disk
is checked against what the script intended to write -- if they ever
disagree, you'll get a loud warning instead of a silent mismatch.

Raw per-tool/per-domain logs are written to `<output>_logs/`, next to the
output files.

## Tools used

Runs in two stages: puredns-bruteforce alone, then everything else together.

| Tool | Mode | Role |
|---|---|---|
| puredns bruteforce | active, DNS only, stage 1, isolated | massdns wordlist run, wildcard-filtered |
| amass | `-passive`: pure OSINT source aggregation, no DNS resolution | enumeration |
| crt.sh | JSON API, no key | certificate transparency |
| subfinder | passive | source aggregator |
| assetfinder | passive | source aggregator |
| findomain | passive | source aggregator |
| gau | passive | archived URLs (Wayback Machine, OTX, Common Crawl, urlscan) |
| alterx + puredns resolve | active, DNS only | permutations on what's already been found, enriched with real suffixes/words pulled from the results themselves (`-enrich`) |
| wordlist x fragment cross-product + puredns resolve | active, DNS only | every contiguous prefix/suffix slice of what's already been found (e.g. finding `adminium-staging-aws-de-fra-1.domain.com` yields fragments like `staging`, `aws-de-fra-1`) crossed against the bruteforce wordlist -- catches the target's own naming convention where alterx's `-enrich` alone doesn't do a full cross-product |
| final puredns resolve pass | active, DNS only | re-validates everything collected before writing `dump_confirmed.txt` -- skips anything puredns-bruteforce/permutations already confirmed, only re-checks what crt.sh/subfinder/assetfinder/findomain/gau/amass turned up |

amass used to run in Normal/active mode with its own isolated stage, but even
Normal mode's netblock/ASN reverse-whois mapping (not gated behind `-active`)
made it consistently the slowest thing in the whole run. It's `-passive` now
-- pure source aggregation, no DNS work of its own, so it runs in the shared
pool with the other passive tools. This is fine accuracy-wise: the final
puredns resolve pass DNS-validates everything regardless of source, so amass
doing its own validation was redundant work anyway.

puredns-bruteforce keeps its own isolated stage: it floods DNS with wordlist
queries, which starves crt.sh/subfinder/assetfinder/findomain/gau's own HTTP
calls of DNS resolution capacity when run alongside them (crt.sh in particular
started failing with "Temporary failure in name resolution", a local-resolver
symptom, specifically on runs where puredns-bruteforce was active in the same
pool).

Nothing depends on an API key. Anything missing (binary not found, wordlist or
resolvers.txt missing) is simply skipped with a warning -- one tool failing
never takes the rest of the run down with it.

## Error handling

The script is built to always run to completion and always leave you with a
result, even if something along the way goes wrong:

- A crashing/missing/timed-out tool is logged and skipped; the rest of the run
  continues. A timeout still keeps whatever partial output the tool had
  already produced instead of discarding it.
- crt.sh gets its own short per-attempt timeout and retries with backoff (up to
  10 attempts, capped at 60s between tries) -- it's known to be flaky (rate
  limiting, occasional 502s). If the JSON API is still down after all retries,
  it falls back to querying crt.sh's public PostgreSQL instance directly
  (`psql -h crt.sh -p 5432 -U guest certwatch`, no API key) -- same data, a
  different transport that isn't affected by whatever's wrong with the web
  frontend. Needs `psql` installed; skipped silently otherwise.
- subfinder, assetfinder, findomain and gau retry if they exit cleanly but with
  empty output -- for network-heavy tools that's far more often a transient
  connectivity blip than a genuine zero. Skipped if the binary just isn't
  installed.
- gau gets an explicit `--timeout 30 --retries 2` so a single slow/rate-limited
  provider can't make one call hang for several minutes before giving up --
  faster to fail and let the retry-if-empty wrapper try again fresh.
- subfinder excludes the `digitorus` source, which panics (a real Go crash, not
  just an error) on some runs and used to kill the whole subfinder process.
- Malformed lines in `domains.txt` (a full URL, a trailing path or port, mixed
  case, a duplicate) are normalized or skipped with a warning instead of
  breaking a downstream file path or tool invocation.
- If an output file can't be written (disk/permission issue), the script falls
  back to `<output>_logs/<name>_fallback.txt`, and to printing the result to
  stdout as a last resort -- the run's results are never silently lost.
- Every output file is read back right after being written to confirm the line
  count on disk actually matches what was intended -- an encoding/write issue
  shows up as a loud warning immediately instead of a silent mismatch you'd
  only notice by counting later.
- Ctrl+C exits cleanly instead of dumping a stack trace.
- amass and every puredns call (bruteforce, permutations, final validation)
  stream their own live progress straight to the terminal instead of being
  fully buffered until they exit -- without this, a long-running one of these
  looks indistinguishable from a hang.

## Installation (WSL/Debian-based)

```bash
sudo apt update && sudo apt install -y golang-go build-essential git postgresql-client

# amass
sudo apt install amass

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# assetfinder
go install github.com/tomnomnom/assetfinder@latest

# findomain (prebuilt binary, or `cargo install findomain`)
curl -sLO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/

# gau
go install github.com/lc/gau/v2/cmd/gau@latest

# massdns (native dependency of puredns -- without it puredns does nothing)
cd ~/tools
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo make install

# puredns (massdns wrapper: bruteforce + resolve with wildcard filtering)
go install github.com/d3mondev/puredns/v2@latest

# alterx (permutation generation)
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# public DNS resolver list for puredns
curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o ~/resolvers.txt

# wordlist for the bruteforce (seclists)
sudo apt install seclists   # or: git clone https://github.com/danielmiessler/SecLists.git
```

The script looks up each Go-installed binary on `PATH` first, then falls back
to `$(go env GOPATH)/bin` (usually `~/go/bin`) automatically -- so it works
even if you forgot to add that directory to `PATH`. Still worth adding it to
your shell profile for using these tools directly outside the script.

The paths/constants at the top of `Subdomains.py` (`AMASS_BIN`, `RESOLVERS_FILE`,
`BRUTEFORCE_WORDLIST`, `AMASS_PORTS`, etc.) need adjusting if your setup
differs from the default paths above.

## Sites to cross-check by hand

No reliable free API for these -- printed at the end of the run, ready to click:

- Chaos --  `https://chaos.projectdiscovery.io/#/`
- VirusTotal -- `https://www.virustotal.com/gui/domain/{d}/relations`
- Censys -- `https://search.censys.io/certificates?q={d}`
- Merklemap -- `https://www.merklemap.com/search?query=*.{d}`
- AlienVault OTX -- `https://otx.alienvault.com/indicator/domain/{d}`
- SecurityTrails -- `https://securitytrails.com/domain/{d}/dns`
- FullHunt -- `https://fullhunt.io/search?q={d}`
