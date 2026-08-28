#!/usr/bin/env python3
"""
Check external URLs in the user documentation for reachability.

Zensical only validates internal references (links between pages and anchor
targets), so external URLs are never verified during a normal docs build. This
script is the out-of-band replacement for the old `mkdocs-htmlproofer-plugin`
that was dropped in the Zensical migration. Run it manually or on a schedule,
not as part of every build.

Requests are grouped by host: different hosts are checked concurrently, but a
single host is only ever asked for one URL at a time, with a delay in between.
"""

import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

AGENTS = {
    'chrome': ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    'safari': ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.6 Safari/605.1.15"),
    'curl': 'curl/8.7.1',
    'honest': 'binaryninja-docs-link-check (+https://binary.ninja/)',
}

# Check as a reader does by default, so pages that serve browsers something
# different are judged on what the reader actually gets
DEFAULT_AGENT = 'chrome'

# Hosts that refuse browser agents but answer simple clients. Measured, not
# guessed: see the probe results in the commit that added this table. Keys match
# a host exactly or any of its parent domains.
SITE_AGENTS = {
    'sourceforge.net': 'curl',
    'sourceforge.io': 'curl',
    'developer.arm.com': 'curl',
    'developers.redhat.com': 'curl',
}

# Tried in order when the preferred agent is refused, so a host that starts
# blocking browsers does not need a code change to keep being checked
FALLBACK_AGENTS = ('curl', 'honest')

# Hosts that need more room than the default delay. The Internet Archive throttles
# with a 503 during a bulk pass, which reads as a broken link if we go too fast.
SITE_DELAYS = {
    'web.archive.org': 3.0,
    'archive.org': 3.0,
}

# Slack refuses anonymous requests to workspace URLs no matter who is asking, so
# these are unverifiable by nature rather than broken. Pass --no-default-ignores
# to check them anyway.
DEFAULT_IGNORES = (
    r'^https?://slack\.binary\.ninja',
    r'^https?://[^/]*\.slack\.com',
)

# Statuses that mean "the server is there but won't talk to us", which is not
# the same as a broken link
UNVERIFIABLE_STATUSES = {401, 403, 405, 429, 999}

INLINE_LINK = re.compile(r'\]\(\s*<?(https?://[^)\s>]+)')
REFERENCE_DEF = re.compile(r'^\s{0,3}\[[^\]]+\]:\s*<?(https?://[^>\s]+)')
AUTOLINK = re.compile(r'<(https?://[^>\s]+)>')
HTML_ATTR = re.compile(r'(?:href|src)\s*=\s*["\'](https?://[^"\']+)["\']')
INLINE_CODE = re.compile(r'`[^`]*`')
CODE_FENCE = re.compile(r'^\s*(```|~~~)')


def extract_urls(path):
    """Yield (line_number, url) for every external URL in a markdown file."""
    in_fence = False

    with open(path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if CODE_FENCE.match(line):
                in_fence = not in_fence
                continue

            if in_fence:
                continue

            # Backticked URLs are literal text, not links
            line = INLINE_CODE.sub('', line)

            for pattern in (INLINE_LINK, REFERENCE_DEF, AUTOLINK, HTML_ATTR):
                for match in pattern.finditer(line):
                    yield line_num, match.group(1).rstrip('.,;')


def host_of(url):
    return urllib.parse.urlsplit(url).netloc.lower()


def lookup(table, host, default):
    """Value for a host or any of its parent domains, else the default."""
    labels = host.split('.')
    for i in range(len(labels)):
        domain = '.'.join(labels[i:])
        if domain in table:
            return table[domain]
    return default


def agents_for(host, default):
    """Preferred agent for a host, then the fallbacks, without repeats."""
    preferred = lookup(SITE_AGENTS, host, default)
    order = [preferred]
    order.extend(name for name in FALLBACK_AGENTS if name != preferred)
    return order


def request(url, method, timeout, user_agent):
    req = urllib.request.Request(url, method=method, headers={
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if method == 'GET':
            resp.read(1024)
        return resp.status


def attempt(url, timeout, user_agent):
    """One HEAD-then-GET pass. Returns (status, detail); status None if unreachable."""
    detail = ''
    head_status = None

    # HEAD is cheap, but plenty of servers answer it with a status they would
    # never give a real GET, so never trust a failing HEAD on its own
    for method in ('HEAD', 'GET'):
        try:
            status = request(url, method, timeout, user_agent)
        except urllib.error.HTTPError as e:
            status, detail = e.code, e.reason or ''
        except Exception as e:  # timeouts, DNS, TLS, malformed redirects
            detail = f'{type(e).__name__}: {e}'
            continue

        if status >= 400 and method == 'HEAD':
            head_status = status
            continue

        return status, detail if status >= 400 else ''

    # GET never completed, so HEAD's status is the best we have
    if head_status is not None:
        return head_status, detail

    return None, detail


def delay_for(url, args):
    return max(args.delay, lookup(SITE_DELAYS, host_of(url), 0))


def check_url(url, args):
    """Return (status, detail, agent_label). Status is an int, or None if unreachable."""
    result = (None, '', DEFAULT_AGENT)
    delay = delay_for(url, args)

    for label in agents_for(host_of(url), args.agent):
        user_agent = AGENTS.get(label, label)

        for retry in range(args.retries + 1):
            status, detail = attempt(url, args.timeout, user_agent)
            result = (status, detail, label)

            if status == 429 and retry < args.retries:
                time.sleep(delay * (2 ** (retry + 1)))
                continue

            break

        # Anything else is this host's real answer, whoever is asking
        if status not in UNVERIFIABLE_STATUSES:
            return result

        time.sleep(delay)

    return result


def check_host(urls, args):
    """Check one host's URLs in sequence, pausing between requests."""
    results = {}

    for i, url in enumerate(urls):
        if i:
            time.sleep(delay_for(url, args))
        results[url] = check_url(url, args)

    return results


def collect(files, ignores):
    locations = defaultdict(list)
    skipped = 0

    for path in files:
        for line_num, url in extract_urls(path):
            if any(pattern.search(url) for pattern in ignores):
                skipped += 1
                continue
            locations[url].append(f'{path}:{line_num}')

    return locations, skipped


def main():
    parser = argparse.ArgumentParser(
        description='Check external URLs in the user documentation for reachability.')
    parser.add_argument(
        'paths', nargs='*',
        help='Files or directories to check (default: the docs/ directory)')
    parser.add_argument(
        '-i', '--ignore', action='append', default=[], metavar='REGEX',
        help='Skip URLs matching this regex (repeatable)')
    parser.add_argument(
        '--no-default-ignores', action='store_true',
        help=f'Also check the URLs skipped by default ({len(DEFAULT_IGNORES)} patterns)')
    parser.add_argument(
        '-j', '--jobs', type=int, default=12,
        help='Number of hosts to check concurrently (default: 12)')
    parser.add_argument(
        '-t', '--timeout', type=float, default=15.0,
        help='Per-request timeout in seconds (default: 15)')
    parser.add_argument(
        '-r', '--retries', type=int, default=1,
        help='Retries for connection failures and rate limits (default: 1)')
    parser.add_argument(
        '-d', '--delay', type=float, default=0.5,
        help='Seconds between requests to the same host (default: 0.5)')
    parser.add_argument(
        '-a', '--agent', default=DEFAULT_AGENT,
        help=f'Default agent: a name from {sorted(AGENTS)} or a literal '
             f'User-Agent string (default: {DEFAULT_AGENT})')
    parser.add_argument(
        '-s', '--strict', action='store_true',
        help='Also fail on URLs that could not be verified (401/403/429 and friends)')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='List every URL checked, not just the problems')

    args = parser.parse_args()

    if args.paths:
        files = []
        for path_str in args.paths:
            path = Path(path_str)
            if path.is_dir():
                files.extend(sorted(path.rglob('*.md')))
            elif path.is_file():
                files.append(path)
            else:
                print(f'Warning: {path_str} is not a valid file or directory')
    else:
        docs_dir = Path(__file__).parent.parent / 'docs'
        if not docs_dir.exists():
            print(f'Error: docs directory not found at {docs_dir}')
            return 1
        files = sorted(docs_dir.rglob('*.md'))

    patterns = list(args.ignore)
    if not args.no_default_ignores:
        patterns.extend(DEFAULT_IGNORES)

    # One request per unique URL, but report every place it appears
    locations, skipped = collect(files, [re.compile(p) for p in patterns])

    if not locations:
        print('No external URLs found')
        return 0

    by_host = defaultdict(list)
    for url in sorted(locations):
        by_host[host_of(url)].append(url)

    # Start the hosts with the most URLs first; they set the wall clock
    hosts = sorted(by_host.values(), key=len, reverse=True)

    print(f'Checking {len(locations)} unique URL(s) across {len(files)} file(s) '
          f'on {len(by_host)} host(s)...')

    results = {}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for batch in pool.map(lambda urls: check_host(urls, args), hosts):
            results.update(batch)

    broken = []
    unverified = []

    for url in sorted(locations):
        status, detail, agent = results[url]
        note = '' if agent == args.agent else f' (as {agent})'

        if status is None:
            broken.append((url, (detail or 'unreachable') + note))
        elif status in UNVERIFIABLE_STATUSES:
            unverified.append((url, f'HTTP {status}{note}'))
        elif status >= 400:
            broken.append((url, f'HTTP {status}{" " + detail if detail else ""}{note}'))
        elif args.verbose:
            print(f'  OK  {status}  {url}{note}')

    def report(title, entries):
        print(f'\n{title}:')
        for url, reason in entries:
            print(f'  {url}')
            print(f'    {reason}')
            for location in locations[url]:
                print(f'    at {location}')

    if broken:
        report(f'{len(broken)} broken URL(s)', broken)

    if unverified:
        report(f'{len(unverified)} URL(s) could not be verified', unverified)

    print(f'\n{len(locations)} checked, {len(broken)} broken, '
          f'{len(unverified)} unverified, {skipped} ignored')

    if broken or (args.strict and unverified):
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
