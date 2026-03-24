#!/usr/bin/env python3
"""
cyberfeed - a terminal cybersecurity news aggregator

Pulls the latest headlines from top cybersecurity RSS feeds
and displays a clean daily briefing right in your terminal.

Usage:
    python cyberfeed.py                  # show today's briefing
    python cyberfeed.py --limit 20       # show more headlines
    python cyberfeed.py --source thn     # filter by source
    python cyberfeed.py --search rsa     # search headlines
    python cyberfeed.py --list           # list all sources
    python cyberfeed.py --export         # export to markdown
    python cyberfeed.py --event rsac     # RSAC conference mode
    python cyberfeed.py --tag ransomware # filter by threat category
    python cyberfeed.py --ai             # AI powered summaries (needs ANTHROPIC_API_KEY)
    python cyberfeed.py --script         # generate video script from top stories

Dependencies:
    pip install defusedxml certifi
"""

import argparse
import sys
import json
import ssl
import os
import textwrap
import re
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape

try:
    import defusedxml.ElementTree as ET
except ImportError:
    print(
        "WARNING: defusedxml not installed. Install it for safe XML parsing:\n"
        "  pip install defusedxml\n",
        file=sys.stderr,
    )
    import xml.etree.ElementTree as ET


SSL_CTX = None
try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()


RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
MAGENTA = "\033[35m"
RED     = "\033[31m"
BLUE    = "\033[34m"
WHITE   = "\033[97m"
BG_DIM  = "\033[48;5;235m"


FEEDS = {
    "thn": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "color": CYAN,
        "icon": "◆",
    },
    "krebs": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "color": RED,
        "icon": "◆",
    },
    "darkread": {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "color": MAGENTA,
        "icon": "◆",
    },
    "secweek": {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "color": BLUE,
        "icon": "◆",
    },
    "bleeping": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "color": GREEN,
        "icon": "◆",
    },
    "schneier": {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "color": YELLOW,
        "icon": "◆",
    },
    "helpnet": {
        "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/",
        "color": WHITE,
        "icon": "◆",
    },
}


EVENTS = {
    "rsac": {
        "name": "RSAC Conference",
        "keywords": ["rsac", "rsa conference", "rsa 2026", "rsa 2025", "moscone", "innovation sandbox"],
        "extra_feeds": {
            "rsac_blog": {
                "name": "RSAC Blog",
                "url": "https://www.rsaconference.com/library/blog/rss",
                "color": CYAN,
                "icon": "★",
            },
        },
        "banner": "⟐  RSAC Conference Mode",
        "banner_color": CYAN,
    },
    "defcon": {
        "name": "DEF CON",
        "keywords": ["defcon", "def con", "hacker summer camp"],
        "extra_feeds": {},
        "banner": "⟐  DEF CON Mode",
        "banner_color": GREEN,
    },
    "blackhat": {
        "name": "Black Hat",
        "keywords": ["black hat", "blackhat", "bh usa", "bh eu"],
        "extra_feeds": {},
        "banner": "⟐  Black Hat Mode",
        "banner_color": RED,
    },
    "bsides": {
        "name": "BSides",
        "keywords": ["bsides", "b-sides", "security bsides"],
        "extra_feeds": {},
        "banner": "⟐  BSides Mode",
        "banner_color": YELLOW,
    },
}



THREAT_TAGS = {
    "ransomware": {
        "keywords": ["ransomware", "ransom", "extortion", "lockbit", "blackcat", "alphv", "clop", "akira", "rhysida", "medusa"],
        "color": RED,
    },
    "supply chain": {
        "keywords": ["supply chain", "supply-chain", "dependency", "typosquat", "backdoor", "solarwinds", "npm malware", "pypi malware", "package hijack"],
        "color": YELLOW,
    },
    "ai security": {
        "keywords": ["ai security", "ai-powered", "llm", "large language model", "machine learning", "deepfake", "agentic ai", "ai agent", "prompt injection", "ai vulnerability", "artificial intelligence"],
        "color": CYAN,
    },
    "zero day": {
        "keywords": ["zero-day", "zero day", "0-day", "0day", "actively exploited", "in the wild", "cve-202"],
        "color": RED,
    },
    "nation state": {
        "keywords": ["apt", "nation-state", "nation state", "china-linked", "russia-linked", "north korea", "iran-linked", "lazarus", "cozy bear", "fancy bear", "charming kitten", "sandworm", "volt typhoon", "salt typhoon", "espionage"],
        "color": MAGENTA,
    },
    "phishing": {
        "keywords": ["phishing", "spear-phishing", "social engineering", "credential theft", "credential harvesting", "bec", "business email"],
        "color": YELLOW,
    },
    "data breach": {
        "keywords": ["data breach", "data leak", "leaked", "exposed data", "records stolen", "records exposed", "user data", "breach after"],
        "color": RED,
    },
    "malware": {
        "keywords": ["malware", "trojan", "infostealer", "info-stealer", "wiper", "botnet", "rat ", "remote access trojan", "loader", "stealer"],
        "color": GREEN,
    },
    "vulnerability": {
        "keywords": ["vulnerability", "vulnerabilities", "rce", "remote code execution", "privilege escalation", "sql injection", "xss", "cisa kev", "patch", "critical flaw"],
        "color": BLUE,
    },
    "cloud": {
        "keywords": ["cloud security", "aws", "azure", "gcp", "kubernetes", "k8s", "container", "docker", "serverless", "cloud misconfiguration"],
        "color": CYAN,
    },
    "identity": {
        "keywords": ["identity", "iam", "authentication", "mfa", "2fa", "sso", "oauth", "credential", "password", "passkey", "zero trust"],
        "color": BLUE,
    },
}


def tag_article(article):
    """Auto tag an article based on title and summary keywords."""
    tags = []
    text = (article["title"] + " " + article.get("summary", "")).lower()
    for tag_name, tag_info in THREAT_TAGS.items():
        for kw in tag_info["keywords"]:
            if kw.lower() in text:
                tags.append(tag_name)
                break
    article["tags"] = tags
    return article


def format_tags(tags):
    """Return a colored string of tags rendered as terminal bubbles."""
    if not tags:
        return ""
    parts = []
    for t in tags:
        info = THREAT_TAGS.get(t, {})
        color = info.get("color", DIM)
        parts.append(f"{color}[{t}]{RESET}")
    return " ".join(parts)


def _safe_api_call(payload_dict, api_key, timeout=30):
    """Make an Anthropic API call. Sanitizes exceptions to prevent key leakage."""
    try:
        payload = json.dumps(payload_dict).encode("utf-8")

        req = Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        with urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            result = json.loads(resp.read())

        text = ""
        for block in result.get("content", []):
            if block.get("type") == "text":
                text += block["text"]

        return text.strip(), None

    except URLError as e:
        reason = getattr(e, "reason", "unknown network error")
        return None, f"network error: {reason}"
    except json.JSONDecodeError:
        return None, "invalid JSON response from API"
    except Exception:
        return None, "API request failed"


def ai_summarize_batch(articles, count=None):
    """Use the Anthropic API to generate one liner summaries for articles."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(f"  {RED}  ✗ ANTHROPIC_API_KEY not set{RESET}")
        print(f"  {DIM}  export ANTHROPIC_API_KEY=your_key_here{RESET}")
        print()
        return articles

    if count:
        to_summarize = articles[:count]
    else:
        to_summarize = articles

    print(f"  {DIM}  generating AI summaries for {len(to_summarize)} articles...{RESET}")
    print()

    article_list = ""
    for i, a in enumerate(to_summarize):
        article_list += f"[{i}] TITLE: {a['title']}\nSOURCE: {a['source']}\nDESCRIPTION: {a.get('summary', 'No description')}\nURL: {a['link']}\n\n"

    prompt = f"""You are a cybersecurity news analyst. For each article below, write a single concise sentence (under 100 characters) that captures the key takeaway or why it matters. Be specific and technical, not generic. Do not use hyphens or dashes. Do not start with "The".

Respond ONLY with a JSON array of strings, one per article, in the same order. No markdown, no backticks, no preamble.

Articles:
{article_list}"""

    text, err = _safe_api_call(
        {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
    )

    if err:
        print(f"  {DIM}  ⚠ AI summary failed: {err}{RESET}", file=sys.stderr)
        return articles

    try:
        summaries = json.loads(text)
        for i, summary in enumerate(summaries):
            if i < len(to_summarize):
                to_summarize[i]["ai_summary"] = summary
    except (json.JSONDecodeError, TypeError):
        print(f"  {DIM}  ⚠ AI summary returned invalid data{RESET}", file=sys.stderr)

    return articles


def generate_script(articles, top_n=3):
    """Generate a short form video script from the top stories."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    stories = articles[:top_n]

    if api_key:
        return _generate_script_ai(stories, api_key)
    else:
        return _generate_script_local(stories)


def _generate_script_ai(stories, api_key):
    """Use Anthropic API to generate a polished video script."""
    print(f"  {DIM}  generating video script with AI...{RESET}")
    print()

    story_block = ""
    for i, a in enumerate(stories, 1):
        story_block += f"Story {i}: {a['title']}\nSource: {a['source']}\nSummary: {a.get('summary', 'N/A')}\nURL: {a['link']}\n\n"

    prompt = f"""You are a cybersecurity content creator writing scripts for short form video (TikTok/Reels/Shorts style). The style is conversational, technically accurate, no fluff, aimed at a tech savvy audience interested in cybersecurity and AI.

Write a script for a 60 second video covering these top cybersecurity stories of the day. The format should be:

HOOK: An attention grabbing opening line (1 sentence)
STORY 1: 2 to 3 sentences covering the first story with the key technical detail
STORY 2: 2 to 3 sentences covering the second story
STORY 3: 2 to 3 sentences covering the third story
CTA: A closing line that encourages engagement

Rules:
- Do not use hyphens or dashes anywhere
- Keep it conversational, not robotic
- Include specific technical details, not vague statements
- No emojis in the script itself
- Write it as spoken word, not written prose
- Total should be under 180 words

Stories:
{story_block}"""

    text, err = _safe_api_call(
        {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        },
        api_key,
    )

    if err:
        print(f"  {DIM}  ⚠ AI script generation failed, using local template: {err}{RESET}", file=sys.stderr)
        return _generate_script_local(stories)

    return text


def _generate_script_local(stories):
    """Generate a basic script template without AI."""
    lines = []
    lines.append("=" * 50)
    lines.append("VIDEO SCRIPT TEMPLATE")
    lines.append("=" * 50)
    lines.append("")
    lines.append("[HOOK]")
    lines.append(f"Here's what you need to know in cybersecurity today.")
    lines.append("")

    for i, a in enumerate(stories, 1):
        lines.append(f"[STORY {i}]")
        lines.append(f"Title: {a['title']}")
        lines.append(f"Source: {a['source']}")
        oneliner = make_oneliner(a.get("summary", ""), max_len=120)
        if oneliner:
            lines.append(f"Key point: {oneliner}")
        lines.append(f"Link: {a['link']}")
        lines.append("")

    lines.append("[CTA]")
    lines.append("Follow for daily cybersecurity updates.")
    lines.append("")
    lines.append("=" * 50)
    lines.append("  TIP: Set ANTHROPIC_API_KEY for AI generated scripts")
    lines.append("=" * 50)

    return "\n".join(lines)


def print_script(script_text):
    """Pretty print the video script."""
    print()
    print(f"  {DIM}{'─' * 62}{RESET}")
    print(f"  {BOLD}{MAGENTA}  🎬  video script{RESET}  {DIM}short form cybersecurity content{RESET}")
    print(f"  {DIM}{'─' * 62}{RESET}")
    print()

    for line in script_text.split("\n"):
        stripped = line.strip().upper()
        if stripped.startswith("[") or stripped.startswith("HOOK") or stripped.startswith("STORY") or stripped.startswith("CTA"):
            print(f"    {BOLD}{CYAN}{line}{RESET}")
        elif stripped.startswith("="):
            print(f"    {DIM}{line}{RESET}")
        else:
            print(f"    {WHITE}{line}{RESET}")

    print()
    print(f"  {DIM}{'─' * 62}{RESET}")
    print()


def export_script(script_text, path="cyberfeed_script.md"):
    """Export the script to a markdown file."""
    now = datetime.now().strftime("%A, %B %d %Y")
    content = f"# cyberfeed video script\n\n*Generated {now}*\n\n---\n\n{script_text}\n"
    with open(path, "w") as f:
        f.write(content)
    return path


# ── helpers ──────────────────────────────────────────────────

def strip_html(text):
    """Remove HTML tags and decode entities."""
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_date(date_str):
    """Try to parse various date formats from RSS/Atom feeds."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        pass
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
    ]:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def time_ago(dt):
    """Return a human friendly relative time string."""
    if not dt:
        return "recently"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        m = seconds // 60
        return f"{m}m ago"
    if seconds < 86400:
        h = seconds // 3600
        return f"{h}h ago"
    d = seconds // 86400
    if d == 1:
        return "yesterday"
    if d < 30:
        return f"{d}d ago"
    return dt.strftime("%b %d")


def fetch_feed(key, feed_info):
    """Fetch and parse a single RSS/Atom feed. Returns list of articles."""
    articles = []
    try:
        req = Request(
            feed_info["url"],
            headers={"User-Agent": "cyberfeed/1.0 (terminal news aggregator)"},
        )
        with urlopen(req, timeout=10, context=SSL_CTX) as resp:
            data = resp.read()
    except (URLError, OSError) as e:
        print(f"  {DIM}  ⚠ could not reach {feed_info['name']}: {e}{RESET}", file=sys.stderr)
        return articles

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        print(f"  {DIM}  ⚠ could not parse {feed_info['name']}{RESET}", file=sys.stderr)
        return articles

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    # RSS 2.0
    for item in root.findall(".//item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        pub = item.findtext("pubDate", "")
        desc = strip_html(item.findtext("description", ""))
        if title:
            articles.append({
                "source_key": key,
                "source": feed_info["name"],
                "color": feed_info["color"],
                "icon": feed_info["icon"],
                "title": strip_html(title),
                "link": link,
                "date": parse_date(pub),
                "summary": desc[:300] if desc else "",
            })

    # Atom
    for entry in root.findall(".//atom:entry", ns):
        title = entry.findtext("atom:title", "", ns).strip()
        link_el = entry.find("atom:link[@rel='alternate']", ns)
        if link_el is None:
            link_el = entry.find("atom:link", ns)
        link = link_el.get("href", "") if link_el is not None else ""
        pub = entry.findtext("atom:published", "", ns) or entry.findtext("atom:updated", "", ns)
        summary_el = entry.findtext("atom:summary", "", ns) or entry.findtext("atom:content", "", ns)
        desc = strip_html(summary_el) if summary_el else ""
        if title:
            articles.append({
                "source_key": key,
                "source": feed_info["name"],
                "color": feed_info["color"],
                "icon": feed_info["icon"],
                "title": strip_html(title),
                "link": link,
                "date": parse_date(pub),
                "summary": desc[:300] if desc else "",
            })

    return articles


def print_header(event=None):
    """Print the cyberfeed banner."""
    now = datetime.now().strftime("%A, %B %d %Y  %I:%M %p")
    width = 62

    print()
    print(f"  {DIM}{'─' * width}{RESET}")

    if event and event in EVENTS:
        ev = EVENTS[event]
        print(f"  {BOLD}{ev['banner_color']}  {ev['banner']}{RESET}  {DIM}cyberfeed{RESET}")
    else:
        print(f"  {BOLD}{CYAN}  ⟐  cyberfeed{RESET}  {DIM}terminal cybersecurity briefing{RESET}")

    print(f"  {DIM}  {now}{RESET}")
    print(f"  {DIM}{'─' * width}{RESET}")
    print()


def make_oneliner(summary, max_len=200):
    """Extract a clean one line summary from the article description."""
    if not summary:
        return ""
    for sep in [". ", ".\n", "! ", "? "]:
        if sep in summary:
            summary = summary[: summary.index(sep) + 1]
            break
    summary = summary.strip()
    if len(summary) > max_len:
        summary = summary[: max_len - 1].rsplit(" ", 1)[0] + "…"
    return summary


def get_terminal_width():
    """Get the terminal width, default to 80."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def print_article(i, article, verbose=False, show_ai=False):
    """Print a single article entry."""
    color = article["color"]
    tag = article["source"]
    ago = time_ago(article["date"])
    title = article["title"]
    indent = "       "
    tw = get_terminal_width()
    wrap_width = tw - 8  # account for indent

    idx = f"{DIM}{str(i).rjust(3)}{RESET}"
    source_tag = f"{color}{BOLD}{article['icon']} {tag}{RESET}"

    print(f"  {idx}  {source_tag}  {DIM}{ago}{RESET}")

    wrapped_title = textwrap.fill(title, width=wrap_width, initial_indent=indent, subsequent_indent=indent)
    print(f"{BOLD}{WHITE}{wrapped_title}{RESET}")

    if show_ai and article.get("ai_summary"):
        wrapped_summary = textwrap.fill(
            f"→ {article['ai_summary']}", width=wrap_width,
            initial_indent=indent, subsequent_indent=indent + "  "
        )
        print(f"{CYAN}{wrapped_summary}{RESET}")
    else:
        oneliner = make_oneliner(article.get("summary", ""))
        if oneliner:
            wrapped_summary = textwrap.fill(
                oneliner, width=wrap_width,
                initial_indent=indent, subsequent_indent=indent
            )
            print(f"{DIM}{wrapped_summary}{RESET}")

    tags_str = format_tags(article.get("tags", []))
    if tags_str:
        print(f"{indent}{tags_str}")

    print(f"{indent}{DIM}{article['link']}{RESET}")

    if verbose and article["summary"]:
        wrapped = textwrap.fill(article["summary"], width=wrap_width, initial_indent=indent, subsequent_indent=indent)
        print(f"{DIM}{wrapped}{RESET}")

    print()


def export_markdown(articles, path="cyberfeed_briefing.md"):
    """Export the current briefing to a markdown file."""
    now = datetime.now().strftime("%A, %B %d %Y  %I:%M %p")
    lines = [
        f"# cyberfeed briefing",
        f"",
        f"*Generated {now}*",
        f"",
        f"---",
        f"",
    ]
    for i, a in enumerate(articles, 1):
        tags = ", ".join(a.get("tags", []))
        lines.append(f"### {i}. {a['title']}")
        lines.append(f"")
        lines.append(f"**Source:** {a['source']}  ")
        lines.append(f"**When:** {time_ago(a['date'])}  ")
        if tags:
            lines.append(f"**Tags:** {tags}  ")
        lines.append(f"**Link:** {a['link']}")
        if a.get("ai_summary"):
            lines.append(f"")
            lines.append(f"**AI Summary:** {a['ai_summary']}")
        if a["summary"]:
            lines.append(f"")
            lines.append(f"> {a['summary']}")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    with open(path, "w") as f:
        f.write("\n".join(lines))

    return path


# ── main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="cyberfeed: terminal cybersecurity news aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              cyberfeed                          daily briefing
              cyberfeed --event rsac             RSAC conference mode
              cyberfeed --tag ransomware         filter by threat category
              cyberfeed --ai                     AI powered summaries
              cyberfeed --script                 generate video script
              cyberfeed --event rsac --ai        RSAC mode + AI summaries
              cyberfeed --tag "zero day" --ai    zero days with AI summaries
        """),
    )
    parser.add_argument(
        "--limit", "-n", type=int, default=15,
        help="number of headlines to show (default: 15)",
    )
    parser.add_argument(
        "--source", "-s", type=str, default=None,
        help="filter by source key (e.g. thn, krebs, darkread)",
    )
    parser.add_argument(
        "--search", "-q", type=str, default=None,
        help="search headlines by keyword",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="show full article summaries",
    )
    parser.add_argument(
        "--list", "-l", action="store_true",
        help="list all available sources, events, and tags",
    )
    parser.add_argument(
        "--export", "-e", action="store_true",
        help="export briefing to markdown file",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="output as JSON",
    )
    parser.add_argument(
        "--event", type=str, default=None,
        help="activate event mode (rsac, defcon, blackhat, bsides)",
    )
    parser.add_argument(
        "--tag", "-t", type=str, default=None,
        help="filter by threat category (ransomware, ai security, zero day, etc.)",
    )
    parser.add_argument(
        "--ai", action="store_true",
        help="generate AI powered summaries (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--script", action="store_true",
        help="generate a short form video script from top stories",
    )
    parser.add_argument(
        "--script-count", type=int, default=3,
        help="number of stories to include in video script (default: 3)",
    )

    args = parser.parse_args()

    if args.list:
        print()
        print(f"  {BOLD}{CYAN}sources:{RESET}")
        print()
        for key, info in FEEDS.items():
            print(f"    {info['color']}{BOLD}{info['icon']} {key:10}{RESET}  {info['name']}")

        print()
        print(f"  {BOLD}{CYAN}events:{RESET}")
        print()
        for key, info in EVENTS.items():
            print(f"    {info['banner_color']}{BOLD}  {key:10}{RESET}  {info['name']}")

        print()
        print(f"  {BOLD}{CYAN}threat tags:{RESET}")
        print()
        for key, info in THREAT_TAGS.items():
            print(f"    {info['color']}[{key}]{RESET}")

        print()
        print(f"  {DIM}usage: cyberfeed --event rsac --tag ransomware --ai{RESET}")
        print()
        return

    if args.source:
        keys = [k.strip() for k in args.source.split(",")]
        feeds_to_fetch = {k: FEEDS[k] for k in keys if k in FEEDS}
        if not feeds_to_fetch:
            print(f"  {RED}unknown source: {args.source}{RESET}")
            print(f"  {DIM}run cyberfeed --list to see available sources{RESET}")
            return
    else:
        feeds_to_fetch = dict(FEEDS)

    event_config = None
    if args.event:
        event_key = args.event.lower()
        if event_key in EVENTS:
            event_config = EVENTS[event_key]
            feeds_to_fetch.update(event_config.get("extra_feeds", {}))
        else:
            print(f"  {RED}unknown event: {args.event}{RESET}")
            print(f"  {DIM}available events: {', '.join(EVENTS.keys())}{RESET}")
            return

    if not args.json:
        print_header(event=args.event)
        source_count = len(feeds_to_fetch)
        status = f"fetching from {source_count} sources"
        if event_config:
            status += f" (+ {event_config['name']} filter)"
        print(f"  {DIM}  {status}...{RESET}")
        print()

    all_articles = []
    for key, info in feeds_to_fetch.items():
        articles = fetch_feed(key, info)
        all_articles.extend(articles)

    all_articles.sort(key=lambda a: a["date"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

    for a in all_articles:
        tag_article(a)

    if event_config:
        event_keywords = event_config["keywords"]
        filtered = []
        for a in all_articles:
            text = (a["title"] + " " + a.get("summary", "")).lower()
            if any(kw in text for kw in event_keywords):
                filtered.append(a)
        if filtered:
            all_articles = filtered
        else:
            print(f"  {YELLOW}  no {event_config['name']} specific articles found, showing all news{RESET}")
            print()

    if args.tag:
        tag_query = args.tag.lower()
        all_articles = [a for a in all_articles if tag_query in a.get("tags", [])]

    if args.search:
        query = args.search.lower()
        all_articles = [a for a in all_articles if query in a["title"].lower() or query in a.get("summary", "").lower()]

    display = all_articles[: args.limit]

    if not display:
        print(f"  {YELLOW}no articles found.{RESET}")
        if args.tag:
            print(f"  {DIM}  available tags: {', '.join(THREAT_TAGS.keys())}{RESET}")
        return

    show_ai = False
    if args.ai or args.script:
        ai_count = len(display) if args.ai else args.script_count
        all_articles = ai_summarize_batch(all_articles, count=ai_count)
        display = all_articles[: args.limit]
        show_ai = args.ai

    if args.script:
        script_stories = all_articles[: args.script_count]
        script_text = generate_script(script_stories, top_n=args.script_count)
        print_script(script_text)

        if args.export:
            path = export_script(script_text)
            print(f"  {GREEN}  ✓ script exported to {path}{RESET}")
            print()
        return

    if args.json:
        out = []
        for a in display:
            out.append({
                "source": a["source"],
                "title": a["title"],
                "link": a["link"],
                "date": a["date"].isoformat() if a["date"] else None,
                "summary": a["summary"],
                "tags": a.get("tags", []),
                "ai_summary": a.get("ai_summary", None),
            })
        print(json.dumps(out, indent=2))
        return

    for i, article in enumerate(display, 1):
        print_article(i, article, verbose=args.verbose, show_ai=show_ai)

    print(f"  {DIM}{'─' * 62}{RESET}")
    total = len(all_articles)
    showing = len(display)
    print(f"  {DIM}  showing {showing} of {total} articles from {len(feeds_to_fetch)} sources{RESET}")

    if args.tag:
        print(f"  {DIM}  filtered by tag: {args.tag}{RESET}")

    if showing < total:
        print(f"  {DIM}  use --limit {total} to see all, or --search <keyword> to filter{RESET}")

    all_tags = {}
    for a in all_articles:
        for t in a.get("tags", []):
            all_tags[t] = all_tags.get(t, 0) + 1
    if all_tags:
        sorted_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:5]
        tag_summary = "  ".join(
            f"{THREAT_TAGS[t]['color']}[{t}({c})]{RESET}" for t, c in sorted_tags
        )
        print(f"  {DIM}  top tags: {tag_summary}{RESET}")

    print()

    if args.export:
        path = export_markdown(display)
        print(f"  {GREEN}  ✓ exported to {path}{RESET}")
        print()


if __name__ == "__main__":
    main()
