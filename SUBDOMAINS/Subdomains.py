#!/usr/bin/env python3
"""
Subdomains.py - subdomain enumeration (crt.sh, subfinder, assetfinder,
findomain, gau, amass passively + puredns/alterx DNS bruteforce/permutations),
results merged, deduped, sorted, and DNS-validated into a clean output file.
Meant to run unattended in the background.

Usage and installation: see README.md in this same folder.
"""

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

def resolve_bin(name):
    """Prefer PATH, but fall back to the standard `go install` location: it
    puts binaries in $GOPATH/bin (usually ~/go/bin), which is very commonly
    NOT on PATH even right after a successful `go install`."""
    found = shutil.which(name)
    if found:
        return found
    try:
        gopath = subprocess.run(
            ["go", "env", "GOPATH"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        gopath = ""
    for base in filter(None, [gopath, str(Path.home() / "go")]):
        candidate = Path(base) / "bin" / name
        if candidate.is_file():
            return str(candidate)
    return name  # not found anywhere -- keep the bare name, downstream warns clearly


# ---------------------------------------------------------------------------
# Tool paths - adjust to your setup
# ---------------------------------------------------------------------------
AMASS_BIN             = resolve_bin("amass")
SUBFINDER_BIN         = resolve_bin("subfinder")
ASSETFINDER_BIN       = resolve_bin("assetfinder")
FINDOMAIN_BIN         = resolve_bin("findomain")
GAU_BIN               = resolve_bin("gau")
PUREDNS_BIN           = resolve_bin("puredns")
ALTERX_BIN            = resolve_bin("alterx")
PSQL_BIN              = resolve_bin("psql")
# digitorus source panics (Go panic, not just a clean error) on some subfinder
# runs, killing the whole subfinder process with exit code 2. Excluded until
# upstream fixes it: https://github.com/projectdiscovery/subfinder
SUBFINDER_EXCLUDE_SOURCES = ["digitorus"]
# one resolver IP per line, e.g. https://github.com/trickest/resolvers
RESOLVERS_FILE        = str(Path.home() / "resolvers.txt")
BRUTEFORCE_WORDLIST   = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
# amass v4 has three tiers: -passive (pure OSINT, no DNS at all, fastest),
# "Normal" (neither flag: passive sources + DNS validation), -active (Normal +
# zone transfers/cert grabs/crawling on every discovered host, by far the
# slowest). Active mode was taking way too long, but pure -passive does zero
# DNS confirmation -- Normal is the actual middle ground amass provides for
# "fast but still doing something", so that's what's used here.
AMASS_PORTS = ("66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,"
               "2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,"
               "5802,6346,6347,7001,7002,8000,8080,8443,8888,30821")

# Concurrent tool invocations across all domains combined. Everything here is
# I/O-bound (waiting on a subprocess or the network, not the CPU), so this can
# run well above the core count without a real resource cost.
WORKERS = 15

# crt.sh is a quick JSON API, not a long scan -- give it its own short per-attempt
# timeout instead of the tools' overall timeout, and retry with backoff since it's
# known to be flaky (rate limiting, occasional 502s under load).
CRTSH_TIMEOUT = 20
CRTSH_RETRIES = 10
CRTSH_RETRY_DELAY = 5    # seconds, grows each attempt: 5, 10, 15... capped below
CRTSH_RETRY_DELAY_MAX = 60

HOSTNAME_RE = re.compile(
    # underscore allowed: _dmarc, _domainkey, _acme-challenge, _sip._tcp... are
    # all real, common DNS labels (DMARC/DKIM/SRV/ACME) that recon tools surface
    r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$"
)


def log(msg):  print(f"\033[0;34m[*]\033[0m {msg}")
def ok(msg):   print(f"\033[0;32m[+]\033[0m {msg}")
def warn(msg): print(f"\033[0;33m[!]\033[0m {msg}", file=sys.stderr)


def stderr_snippet(stderr, max_lines=2, max_chars=200):
    """Last couple non-empty stderr lines, trimmed -- the real error is usually
    near the end, and printing it inline saves a trip into the log file."""
    lines = [l.strip() for l in (stderr or "").splitlines() if l.strip()]
    if not lines:
        return ""
    snippet = " | ".join(lines[-max_lines:])
    if len(snippet) > max_chars:
        snippet = snippet[:max_chars] + "..."
    return f": {snippet}"


def run_subprocess(name, cmd, timeout):
    """Run a tool, never raise: return (stdout, stderr), '' on any failure."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        warn(f"{name}: binary not found ({cmd[0]}), skipping")
        return "", ""
    except subprocess.TimeoutExpired as e:
        # e.stdout/e.stderr hold whatever the process had already written
        # before being killed -- salvage it instead of throwing results away.
        partial = e.stdout or ""
        warn(f"{name}: timed out after {timeout}s, keeping {len(partial.splitlines())} lines already captured")
        return partial, (e.stderr or "")
    except OSError as e:
        warn(f"{name}: failed to launch ({e})")
        return "", ""
    if proc.returncode != 0:
        warn(f"{name}: exited with code {proc.returncode}{stderr_snippet(proc.stderr)}")
    elif not proc.stdout.strip() and proc.stderr.strip():
        # exit 0 but nothing found AND something on stderr -- usually means a
        # provider/config issue that didn't trip a nonzero exit code
        warn(f"{name}: produced no output{stderr_snippet(proc.stderr)}")
    return proc.stdout, proc.stderr


def run_subprocess_live(name, cmd, timeout):
    """Like run_subprocess but does NOT capture output -- lets the tool's own
    live progress (puredns prints a real progress bar while resolving) stream
    straight to the terminal instead of vanishing into a fully-buffered pipe
    until exit. Only use this for calls whose actual result comes from a -w/-o
    file, never from stdout, since none of that output is returned here."""
    try:
        proc = subprocess.run(cmd, timeout=timeout)
    except FileNotFoundError:
        warn(f"{name}: binary not found ({cmd[0]}), skipping")
        return False
    except subprocess.TimeoutExpired:
        warn(f"{name}: timed out after {timeout}s")
        return False
    except OSError as e:
        warn(f"{name}: failed to launch ({e})")
        return False
    if proc.returncode != 0:
        warn(f"{name}: exited with code {proc.returncode}")
    return True


def run_with_retry_if_empty(name, cmd, timeout, retries=3, delay=5):
    """Retry if the tool exits cleanly but with empty output. For network-heavy
    tools, an empty result is far more often a transient connectivity blip than
    a genuine zero -- especially when it lines up with crt.sh timeouts/502s or
    DNS resolution errors happening elsewhere in the same run (e.g. from
    puredns-bruteforce hammering DNS at the same time). Skips retrying outright
    if the binary just isn't installed -- retrying that only wastes time."""
    if shutil.which(cmd[0]) is None and not Path(cmd[0]).is_file():
        return run_subprocess(name, cmd, timeout)
    out, err = "", ""
    for attempt in range(1, retries + 1):
        out, err = run_subprocess(name, cmd, timeout)
        if out.strip():
            return out, err
        if attempt < retries:
            warn(f"{name}: empty result on attempt {attempt}/{retries}, retrying in {delay}s")
            time.sleep(delay)
    return out, err


def write_log(logs_dir, domain, tool, out, err=""):
    content = out or ""
    if err:
        content += f"\n--- stderr ---\n{err}"
    (logs_dir / f"{domain}__{tool}.txt").write_text(
        content, encoding="utf-8", errors="replace"
    )


def clean_lines(text, domain):
    """Normalize raw tool output into a set of valid hosts under `domain`."""
    domain = domain.lower()
    found = set()
    for raw in (text or "").splitlines():
        h = raw.strip().lower()
        if not h:
            continue
        if h.startswith("*."):
            h = h[2:]
        if h.endswith("."):
            h = h[:-1]
        if not HOSTNAME_RE.match(h):
            continue
        if h != domain and not h.endswith("." + domain):
            continue
        found.add(h)
    return found


# ---------------------------------------------------------------------------
# individual tools
# ---------------------------------------------------------------------------

def task_amass(domain, timeout, logs_dir):
    # writes straight to -o instead of only returning stdout at the end: this
    # lets you `tail -f` the log file to see it's actually making progress
    # during a long run, and salvages real progress even if it gets killed by
    # the timeout.
    #
    # -passive: pure OSINT source aggregation, no DNS resolution, no netblock/
    # ASN reverse-whois mapping -- that network-mapping behavior turned out to
    # not be gated behind -active, it's core to amass and was still making
    # "Normal" mode slow. -passive skips it entirely and runs comparably fast
    # to the other source aggregators (subfinder, crt.sh...). This is fine
    # accuracy-wise because resolve_stage DNS-validates everything at the end
    # regardless of source -- amass doing its own validation was redundant.
    # -p (AMASS_PORTS) has no effect in -passive mode (nothing gets contacted).
    out_file = logs_dir / f"{domain}__amass.txt"
    amass_dir = logs_dir / f"{domain}__amass_dir"
    # -v surfaces per-source status live; -dir pins amass's own internal
    # amass.log (it logs errors there, not necessarily to stdout/stderr)
    # somewhere we can go find it instead of a hidden default path. Uses the
    # live-streaming runner (like the big puredns calls) instead of the fully-
    # buffered one -- amass querying ~40 sources with nothing printed until it
    # exits looked indistinguishable from a hang; the actual result is read
    # from -o below regardless, so nothing is lost by not capturing stdout/err.
    cmd = [AMASS_BIN, "enum", "-v", "-passive", "-d", domain,
           "-dir", str(amass_dir), "-o", str(out_file)]
    run_subprocess_live("amass", cmd, timeout)
    raw = out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else ""
    # amass v4's -o dumps the asset relationship graph as event lines, e.g.
    # "sub.domain.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)", not a plain
    # name list like v3 used to produce. Pull out every entity tagged (FQDN);
    # clean_lines() downstream filters to the ones that actually belong to `domain`.
    return "\n".join(re.findall(r"(\S+) \(FQDN\)", raw))


def task_subfinder(domain, timeout, logs_dir):
    cmd = [SUBFINDER_BIN, "-d", domain, "-silent"]
    if SUBFINDER_EXCLUDE_SOURCES:
        cmd += ["-exclude-sources", ",".join(SUBFINDER_EXCLUDE_SOURCES)]
    out, err = run_with_retry_if_empty("subfinder", cmd, timeout)
    write_log(logs_dir, domain, "subfinder", out, err)
    return out


def task_assetfinder(domain, timeout, logs_dir):
    out, err = run_with_retry_if_empty("assetfinder", [ASSETFINDER_BIN, "--subs-only", domain], timeout)
    write_log(logs_dir, domain, "assetfinder", out, err)
    return out


def crtsh_via_psql(domain, timeout, logs_dir):
    """Fallback for when crt.sh's HTTP/JSON frontend is having a bad day: query
    its public PostgreSQL instance directly instead -- same underlying data,
    a completely different transport (bypasses whatever web-layer issue causes
    the 502/503/404/timeout pattern), no API key. This is a long-documented,
    still-supported crt.sh feature, not an unofficial workaround. Needs the
    `psql` client installed."""
    if shutil.which(PSQL_BIN) is None:
        return None
    domain_escaped = domain.replace("'", "''")  # defense in depth, not strictly needed
    query = ("SELECT ci.NAME_VALUE FROM certificate_identity ci "
              "WHERE ci.NAME_TYPE = 'dNSName' "
             f"AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{domain_escaped}'));")
    cmd = [PSQL_BIN, "-t", "-A", "-h", "crt.sh", "-p", "5432", "-U", "guest", "certwatch", "-c", query]
    out, err = run_subprocess("crt.sh (psql)", cmd, timeout)
    if not out.strip():
        return None
    write_log(logs_dir, domain, "crtsh_psql", out, err)
    return out


def task_crtsh(domain, timeout, logs_dir):
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Subdomains.py)"})
    data, last_err = None, None
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as resp:
                data = json.load(resp)
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            last_err = e
            if attempt < CRTSH_RETRIES:
                delay = min(CRTSH_RETRY_DELAY * attempt, CRTSH_RETRY_DELAY_MAX)
                warn(f"crt.sh: attempt {attempt}/{CRTSH_RETRIES} failed ({e}), retrying in {delay}s")
                time.sleep(delay)

    if data is not None:
        names = set()
        for entry in data:
            for n in entry.get("name_value", "").splitlines():
                n = n.strip()
                if n:
                    names.add(n)
        text = "\n".join(sorted(names))
        write_log(logs_dir, domain, "crtsh", text)
        return text

    warn(f"crt.sh: JSON API exhausted after {CRTSH_RETRIES} attempts ({last_err}), "
         "trying direct Postgres access instead")
    psql_text = crtsh_via_psql(domain, CRTSH_TIMEOUT, logs_dir)
    if psql_text:
        ok("crt.sh: direct Postgres access succeeded where the JSON API didn't")
        return psql_text
    warn("crt.sh: direct Postgres access also failed or unavailable (psql installed?), giving up")
    write_log(logs_dir, domain, "crtsh", "")
    return ""


def task_puredns_bruteforce(domain, timeout, logs_dir):
    # DNS-only wordlist bruteforce (massdns under the hood): no HTTP requests hit
    # the target, and puredns filters wildcard DNS false-positives that raw massdns
    # would happily report as "found" on any CDN-fronted domain.
    if shutil.which(PUREDNS_BIN) is None:
        warn("puredns: binary not found, skipping bruteforce")
        return ""
    if not Path(BRUTEFORCE_WORDLIST).is_file():
        warn(f"puredns: wordlist not found ({BRUTEFORCE_WORDLIST}), skipping bruteforce")
        return ""
    if not Path(RESOLVERS_FILE).is_file():
        warn(f"puredns: resolvers file not found ({RESOLVERS_FILE}), skipping bruteforce")
        return ""
    out_file = logs_dir / f"{domain}__puredns_bruteforce.txt"
    cmd = [PUREDNS_BIN, "bruteforce", BRUTEFORCE_WORDLIST, domain,
           "-r", RESOLVERS_FILE, "-w", str(out_file), "-q"]
    run_subprocess_live("puredns", cmd, timeout)
    return out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else ""


def task_findomain(domain, timeout, logs_dir):
    out, err = run_with_retry_if_empty("findomain", [FINDOMAIN_BIN, "-t", domain, "-q"], timeout)
    write_log(logs_dir, domain, "findomain", out, err)
    return out


def task_gau(domain, timeout, logs_dir):
    # gau covers Wayback Machine + AlienVault OTX + Common Crawl + urlscan.io in
    # one tool (superset of tomnomnom/waybackurls, and more actively maintained).
    # --subs is required to get subdomains at all -- without it gau only returns
    # URLs for the exact domain given. Prints full URLs, not bare hostnames.
    # --timeout/--retries bound gau's OWN internal HTTP client -- without them
    # a single slow/rate-limited provider can make one gau call hang for several
    # minutes before giving up, which is slower than just letting our own
    # retry-if-empty wrapper cycle to a fresh attempt.
    cmd = [GAU_BIN, "--subs", "--timeout", "30", "--retries", "2", domain]
    out, err = run_with_retry_if_empty("gau", cmd, timeout)
    write_log(logs_dir, domain, "gau", out, err)
    hosts = set()
    for line in out.splitlines():
        host = urllib.parse.urlparse(line.strip()).hostname
        if host:
            hosts.add(host)
    return "\n".join(sorted(hosts))


TASKS = {
    "crt.sh": task_crtsh,
    "subfinder": task_subfinder,
    "assetfinder": task_assetfinder,
    "findomain": task_findomain,
    "gau": task_gau,
    # amass runs -passive now (see task_amass) -- no DNS resolution of its own
    # means no contention with puredns-bruteforce, so it's back in the shared
    # pool instead of needing its own isolated stage.
    "amass": task_amass,
}

# Tasks whose output already went through a puredns resolve (wildcard-filtered,
# DNS-confirmed) -- resolve_stage skips re-checking these at the end instead of
# querying DNS a second time for something we already know resolves.
DNS_VALIDATED_TASKS = {"puredns-bruteforce"}

# puredns-bruteforce floods DNS, and starves crt.sh/subfinder/assetfinder/
# findomain/gau's own HTTP calls of DNS resolution capacity when run alongside
# them -- crt.sh in particular started failing with "Temporary failure in name
# resolution" (a *local* resolver symptom, not a crt.sh problem) specifically
# on runs where puredns-bruteforce was active in the same pool. Isolated into
# its own stage for that reason (amass used to be isolated for the same reason
# back when it did its own DNS resolution -- now that it's -passive, it moved
# back into the shared TASKS pool above).
BRUTEFORCE_TASK = {"puredns-bruteforce": task_puredns_bruteforce}


# A fragment seen on only one host is usually just an artifact of that one
# name, not a reusable convention -- require it to recur on at least this many
# DISTINCT hosts before it's trusted enough to cross against the wordlist.
FRAGMENT_MIN_OCCURRENCES = 2
# Hard ceiling on generated candidates regardless of the above -- a rich seed
# list can still produce hundreds of thousands of fragment combinations, and
# puredns resolving over a million candidates with zero visible progress reads
# as a hang even when it's working fine.
MAX_PERMUTATION_CANDIDATES = 150_000


def extract_fragments(seed, domain):
    """Every contiguous leading/trailing slice of the leftmost label's hyphen-
    split tokens, gathered across everything already found, kept only if it
    recurs on >= FRAGMENT_MIN_OCCURRENCES distinct hosts. E.g. finding
    adminium-staging-aws-de-fra-1.domain.com yields prefix candidate
    "adminium-staging" and suffix candidates "staging-aws-de-fra-1" and
    "aws-de-fra-1" -- this naturally captures compound env+region tokens
    without having to hardcode what an "environment" or "region" looks like,
    while the recurrence filter drops the long one-off compound slices that
    are the main source of candidate explosion."""
    dsuffix = "." + domain
    prefix_counts, suffix_counts = Counter(), Counter()
    for host in seed:
        if host == domain or not host.endswith(dsuffix):
            continue
        tokens = host[: -len(dsuffix)].split(".")[0].split("-")
        if len(tokens) < 2:
            continue
        # count each fragment once per host, not once per slice position
        prefix_counts.update({"-".join(tokens[:i]) for i in range(1, len(tokens))})
        suffix_counts.update({"-".join(tokens[i:]) for i in range(1, len(tokens))})

    def keep(token, count):
        return count >= FRAGMENT_MIN_OCCURRENCES and len(token) >= 2 and not token.isdigit()

    prefixes = {p for p, c in prefix_counts.items() if keep(p, c)}
    suffixes = {s for s, c in suffix_counts.items() if keep(s, c)}
    return prefixes, suffixes


def wordlist_fragment_candidates(seed, domain, wordlist_path):
    """Cross a big generic wordlist with the target's own observed naming
    fragments -- far more likely to hit than either a generic wordlist alone
    or a generic permutation pattern list. Fragments are NOT crossed against
    each other: compound-on-compound (e.g. "aws-de-fra-1-fra-1") is noise that
    will basically never resolve, just wasted DNS queries."""
    prefixes, suffixes = extract_fragments(seed, domain)
    if not prefixes and not suffixes:
        return set()
    try:
        words = {w.strip() for w in Path(wordlist_path).read_text(
            encoding="utf-8", errors="replace").splitlines() if w.strip()}
    except OSError:
        words = set()
    if not words:
        return set()

    candidates = set()
    for word in words:
        for suf in suffixes:
            candidates.add(f"{word}-{suf}.{domain}")
        for pre in prefixes:
            candidates.add(f"{pre}-{word}.{domain}")

    if len(candidates) > MAX_PERMUTATION_CANDIDATES:
        warn(f"permutations: {len(candidates)} candidates from {len(prefixes)} prefixes / "
             f"{len(suffixes)} suffixes x {len(words)} words -- capping to a random "
             f"{MAX_PERMUTATION_CANDIDATES} sample to keep the resolve pass reasonable")
        candidates = set(random.sample(sorted(candidates), MAX_PERMUTATION_CANDIDATES))
    return candidates


def resolve_stage(per_domain, already_confirmed, timeout, logs_dir, workers):
    """Final DNS-confirmation pass over what's left. crt.sh/subfinder/
    assetfinder/findomain/gau are only format-validated (regex + domain
    suffix), never DNS-checked -- a parsing artifact that happens to look like
    a valid hostname (e.g. two archived URLs glued together with no separator,
    seen in practice from gau) can slip through undetected. Anything already
    in `already_confirmed` (puredns-bruteforce, permutations) already went
    through a puredns resolve -- skip re-querying DNS for those, just carry
    them over. Returns None if validation couldn't run at all (missing
    puredns/resolvers), or a dict of domain -> confirmed set otherwise."""
    if shutil.which(PUREDNS_BIN) is None:
        warn("puredns: binary not found, skipping final DNS validation")
        return None
    if not Path(RESOLVERS_FILE).is_file():
        warn(f"puredns: resolvers file not found ({RESOLVERS_FILE}), skipping final DNS validation")
        return None

    def run_one(domain):
        hosts = per_domain[domain]
        already = already_confirmed.get(domain, set()) & hosts
        to_check = hosts - already
        if not to_check:
            return domain, set(already)
        candidates_file = logs_dir / f"{domain}__final_candidates.txt"
        candidates_file.write_text("\n".join(sorted(to_check)), encoding="utf-8")
        resolved_file = logs_dir / f"{domain}__final_resolved.txt"
        run_subprocess_live("puredns", [PUREDNS_BIN, "resolve", str(candidates_file),
                                         "-r", RESOLVERS_FILE, "-w", str(resolved_file), "-q"], timeout)
        newly_confirmed = set()
        if resolved_file.is_file():
            text = resolved_file.read_text(encoding="utf-8", errors="replace")
            newly_confirmed = clean_lines(text, domain)
        return domain, already | newly_confirmed

    confirmed = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_one, d): d for d in per_domain}
        for fut in as_completed(futures):
            domain = futures[fut]
            try:
                domain, result = fut.result()
            except Exception as e:  # same rule as every other stage: never take the run down
                warn(f"{domain} / final DNS check: unhandled error: {e}")
                result = set()
            skipped = len(already_confirmed.get(domain, set()) & per_domain[domain])
            dropped = len(per_domain[domain]) - len(result)
            log(f"{domain}: final DNS check confirmed {len(result)}/{len(per_domain[domain])}"
                f" ({skipped} already known, {len(per_domain[domain]) - skipped} re-checked)"
                + (f", {dropped} did not resolve" if dropped else ""))
            confirmed[domain] = result
    return confirmed


def write_clean_file(path, items, logs_dir, label):
    """Write a sorted/deduped list, then read it back and verify the line
    count actually on disk matches what we intended -- removes any chance of
    the script reporting a count that doesn't match the real file. Falls back
    to logs_dir, then stdout, if the primary path can't be written."""
    text = "\n".join(sorted(items)) + ("\n" if items else "")
    target = path
    try:
        target.write_text(text, encoding="utf-8")
    except OSError as e:
        warn(f"{label}: could not write {path} ({e}), trying a fallback location")
        fallback = logs_dir / f"{path.stem}_fallback.txt"
        try:
            fallback.write_text(text, encoding="utf-8")
            target = fallback
        except OSError as e2:
            warn(f"{label}: fallback write to {fallback} also failed ({e2}), dumping to stdout instead")
            print(text)
            return None

    try:
        actual = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError as e:
        warn(f"{label}: wrote {target} but could not read it back to verify ({e})")
        return target
    if actual != len(items):
        warn(f"{label}: wrote {len(items)} entries but {target} has {actual} lines on disk "
             f"-- mismatch, check for encoding/write issues")
    else:
        ok(f"{label}: {actual} lines confirmed on disk -> {target}")
    return target


def permutation_stage(per_domain, timeout, logs_dir, workers, already_confirmed):
    """alterx generates permutations (dev-api, api-dev, staging2...) from what
    was already found; a wordlist x observed-fragments cross-product adds
    candidates alterx's own pattern logic doesn't reach; puredns resolves the
    lot (DNS-only, wildcard-filtered) and any hit gets folded back into
    per_domain (and already_confirmed, since it just went through puredns) in
    place."""
    # puredns is the one hard requirement -- it's what actually resolves and
    # wildcard-filters candidates regardless of which source generated them.
    if shutil.which(PUREDNS_BIN) is None:
        warn("puredns: binary not found, skipping permutations")
        return
    if not Path(RESOLVERS_FILE).is_file():
        warn(f"puredns: resolvers file not found ({RESOLVERS_FILE}), skipping permutations")
        return
    have_alterx = shutil.which(ALTERX_BIN) is not None
    if not have_alterx:
        warn("alterx: binary not found, skipping alterx source (wordlist x fragments still runs)")

    def run_one(domain):
        seed = per_domain[domain]
        if not seed:
            return domain, set()
        seed_file = logs_dir / f"{domain}__alterx_seed.txt"
        seed_file.write_text("\n".join(sorted(seed)), encoding="utf-8")

        candidates = set()
        if have_alterx:
            perm_file = logs_dir / f"{domain}__alterx.txt"
            # -enrich extracts real recurring words/suffixes from the seed itself
            # (e.g. -staging, -dev, -prd, -interf, -aws-de-fra-1) instead of only
            # using the generic default wordlist -- targets are far more likely
            # to reuse their own naming conventions than a generic pattern list.
            run_subprocess("alterx", [ALTERX_BIN, "-l", str(seed_file), "-o", str(perm_file),
                                       "-enrich", "-silent"], timeout)
            if perm_file.is_file():
                candidates |= {l.strip() for l in perm_file.read_text(
                    encoding="utf-8", errors="replace").splitlines() if l.strip()}

        frag_candidates = wordlist_fragment_candidates(seed, domain, BRUTEFORCE_WORDLIST)
        candidates |= frag_candidates
        log(f"{domain} / permutations: {len(frag_candidates)} wordlist x fragment "
            f"candidates + alterx, {len(candidates)} total to resolve")

        if not candidates:
            return domain, set()
        combined_file = logs_dir / f"{domain}__permutation_candidates.txt"
        combined_file.write_text("\n".join(sorted(candidates)), encoding="utf-8")

        resolved_file = logs_dir / f"{domain}__puredns_permutations.txt"
        run_subprocess_live("puredns", [PUREDNS_BIN, "resolve", str(combined_file),
                                         "-r", RESOLVERS_FILE, "-w", str(resolved_file), "-q"], timeout)
        if not resolved_file.is_file():
            return domain, set()
        text = resolved_file.read_text(encoding="utf-8", errors="replace")
        return domain, clean_lines(text, domain)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_one, d): d for d in per_domain}
        for fut in as_completed(futures):
            domain = futures[fut]
            try:
                domain, new = fut.result()
            except Exception as e:  # same rule as the main pool: never take the run down
                warn(f"{domain} / alterx+puredns: unhandled error: {e}")
                continue
            added = new - per_domain[domain]
            if added:
                log(f"{domain} / alterx+puredns: +{len(added)} new hosts via permutation")
            per_domain[domain] |= new
            already_confirmed[domain] |= new


# Free sites/datasets worth cross-checking by hand -- not automated here (no API
# key wired in, or no reliable query URL). Printed as ready-to-click links at the
# end of the run.
CROSS_REFERENCE_SITES = [
    ("Chaos (ProjectDiscovery)", "https://chaos.projectdiscovery.io/#/"),
    ("VirusTotal",     "https://www.virustotal.com/gui/domain/{d}/relations"),
    ("Censys",         "https://search.censys.io/certificates?q={d}"),
    ("Merklemap",      "https://www.merklemap.com/search?query=*.{d}"),
    ("AlienVault OTX", "https://otx.alienvault.com/indicator/domain/{d}"),
    ("SecurityTrails", "https://securitytrails.com/domain/{d}/dns"),
    ("FullHunt",       "https://fullhunt.io/search?q={d}"),
]


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def normalize_domain(domain_raw):
    """Tolerate messy domains.txt lines (URL instead of bare domain, trailing
    path/port, stray case) so a typo can never turn into a broken file path or
    a nonsense tool invocation further down the pipeline."""
    domain = domain_raw.strip()
    if domain.startswith("*."):
        domain = domain[2:]
    domain = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)  # strip a URL scheme
    domain = domain.split("/", 1)[0]                             # strip any path
    domain = domain.split(":", 1)[0]                             # strip any port
    domain = domain.strip().strip(".").lower()
    return domain


def run_stage(tasks, domains, timeout, logs_dir, per_domain, already_confirmed=None):
    """Run every (domain, tool) pair from `tasks` in one shared pool, merging
    results into `per_domain` in place as they complete. Results from a task
    listed in DNS_VALIDATED_TASKS are also mirrored into `already_confirmed`
    so resolve_stage can skip re-checking them later."""
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(fn, domain, timeout, logs_dir): (domain, name)
            for domain in domains
            for name, fn in tasks.items()
        }
        for fut in as_completed(futures):
            domain, name = futures[fut]
            try:
                text = fut.result()
            except Exception as e:  # a tool must never take the whole run down
                warn(f"{domain} / {name}: unhandled error: {e}")
                text = ""
            new = clean_lines(text, domain)
            per_domain[domain] |= new
            if already_confirmed is not None and name in DNS_VALIDATED_TASKS:
                already_confirmed[domain] |= new
            log(f"{domain} / {name}: {len(new)} hosts")


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain recon: merges, permutes and DNS-validates into "
                     "dump.txt (raw) and dump_confirmed.txt (DNS-confirmed subset)")
    parser.add_argument("-d", "--domains", required=True, help="file with one domain (or *.domain) per line")
    parser.add_argument("-o", "--output", default="dump.txt",
                         help="base name for the output files (raw + _confirmed variant)")
    parser.add_argument("-t", "--timeout", type=int, default=1800,
                         help="per-tool timeout in seconds (default 30min)")
    parser.add_argument("--skip-amass", action="store_true",
                         help="skip amass entirely (faster iteration while testing)")
    args = parser.parse_args()

    domains_file = Path(args.domains)
    if not domains_file.is_file():
        sys.exit(f"[-] no such file: {domains_file}")
    try:
        raw_text = domains_file.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        sys.exit(f"[-] could not read {domains_file}: {e}")

    out_path = Path(args.output)
    logs_dir = out_path.parent / f"{out_path.stem}_logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"[-] could not create logs dir {logs_dir}: {e}")

    domains = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = normalize_domain(line)
        if not domain:
            warn(f"skipping unparsable line in {domains_file}: {line!r}")
            continue
        if domain not in domains:
            domains.append(domain)

    if not domains:
        sys.exit("[-] no domains to process")

    # every (domain, tool) pair in a stage runs in ONE shared pool: domain B's
    # tool starts immediately instead of waiting for domain A's slowest tool to
    # finish first, which is what actually made multi-domain runs slow.
    per_domain = {d: set() for d in domains}
    # hosts already confirmed by a puredns resolve pass earlier in the run
    # (puredns-bruteforce, permutations) -- resolve_stage skips re-querying
    # DNS for these instead of doing the same work twice.
    already_confirmed = {d: set() for d in domains}
    start = time.time()

    log("stage 1/2: puredns-bruteforce, isolated (floods DNS -- would starve "
        "crt.sh/subfinder/assetfinder/findomain/gau's own HTTP calls if run "
        "alongside them)")
    run_stage(BRUTEFORCE_TASK, domains, args.timeout, logs_dir, per_domain, already_confirmed)

    tasks = dict(TASKS)
    if args.skip_amass:
        del tasks["amass"]
    log(f"stage 2/2: {', '.join(tasks)}")
    run_stage(tasks, domains, args.timeout, logs_dir, per_domain, already_confirmed)

    for domain in domains:
        ok(f"{domain}: {len(per_domain[domain])} unique candidates merged, "
           f"feeding permutations (see <output>_logs/{domain}__alterx_seed.txt)")
    permutation_stage(per_domain, args.timeout, logs_dir, WORKERS, already_confirmed)

    all_found = set()
    for domain in domains:
        ok(f"{domain}: {len(per_domain[domain])} unique subdomains")
        all_found |= per_domain[domain]

    log("final DNS validation: confirming every candidate actually resolves "
        "(catches format-valid-but-fake entries crt.sh/subfinder/assetfinder/"
        "findomain/gau never got DNS-checked for; skips re-checking what "
        "puredns-bruteforce/permutations already confirmed)")
    confirmed = resolve_stage(per_domain, already_confirmed, args.timeout, logs_dir, WORKERS)
    all_confirmed = None
    if confirmed is not None:
        all_confirmed = set()
        for domain in domains:
            all_confirmed |= confirmed.get(domain, set())

    written_raw = write_clean_file(out_path, all_found, logs_dir, "raw merged")
    written_confirmed = None
    confirmed_path = out_path.parent / f"{out_path.stem}_confirmed{out_path.suffix}"
    if all_confirmed is not None:
        written_confirmed = write_clean_file(confirmed_path, all_confirmed, logs_dir, "DNS-confirmed")

    elapsed = time.time() - start
    print()
    ok(f"Done in {elapsed:.0f}s.")
    ok(f"{len(all_found)} raw unique subdomains -> {written_raw or '(not written, see stdout above)'}")
    if all_confirmed is not None:
        ok(f"{len(all_confirmed)} DNS-confirmed subset -> {written_confirmed or '(not written, see stdout above)'}")
    else:
        warn(f"{out_path} is raw/unconfirmed only -- DNS validation was skipped (puredns/resolvers unavailable)")
    ok(f"Raw per-tool/per-domain output kept in: {logs_dir}")

    print("\nManually cross-check with:")
    for domain in domains:
        print(f"  {domain}:")
        for name, template in CROSS_REFERENCE_SITES:
            print(f"    - {name}: {template.format(d=domain)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warn("interrupted by user")
        sys.exit(130)
