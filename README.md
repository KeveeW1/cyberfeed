# cyberfeed
a terminal cybersecurity news aggregator that pulls headlines from top security RSS feeds and displays a clean daily briefing right in your terminal.

if you have any feedback or additions, lmk on X tyty;
<i>still learning</i>

## install

```bash
pip install defusedxml certifi
```

clone the repo and run:

```bash
python cyberfeed.py
```

## usage

```bash
cyberfeed                              # daily briefing
cyberfeed --limit 30                   # show more headlines
cyberfeed --source krebs,thn           # filter by source
cyberfeed --search "salt typhoon"      # search headlines
cyberfeed --tag ransomware             # filter by threat category
cyberfeed --tag "zero day"             # tags with spaces need quotes
cyberfeed --event rsac                 # conference mode
cyberfeed --export                     # export to markdown
cyberfeed --json                       # output as JSON
cyberfeed --list                       # list all sources, events, and tags
```

### AI features

requires an [Anthropic API key](https://console.anthropic.com/):

```bash
export ANTHROPIC_API_KEY=your_key_here

cyberfeed --ai                         # AI powered one liner summaries
cyberfeed --script                     # generate a short form video script
cyberfeed --script --export            # export the script to markdown
cyberfeed --event rsac --ai            # combine modes
```

without the API key, `--script` still works using a local template.

## sources

| key | source |
|-----|--------|
| `thn` | The Hacker News |
| `krebs` | Krebs on Security |
| `darkread` | Dark Reading |
| `secweek` | SecurityWeek |
| `bleeping` | BleepingComputer |
| `schneier` | Schneier on Security |
| `helpnet` | Help Net Security |

## threat tags

articles are auto tagged based on title and summary keywords:

`ransomware` · `supply chain` · `ai security` · `zero day` · `nation state` · `phishing` · `data breach` · `malware` · `vulnerability` · `cloud` · `identity`

## conference modes

track coverage from major security conferences. adds event specific keyword filtering and (where available) extra RSS feeds:

```bash
cyberfeed --event rsac
cyberfeed --event defcon
cyberfeed --event blackhat
cyberfeed --event bsides
```

## video script generation

generate short form video scripts (TikTok / Reels / Shorts) from the top stories of the day:

```bash
cyberfeed --script                     # default top 3 stories
cyberfeed --script --script-count 5    # include 5 stories
cyberfeed --script --export            # save to cyberfeed_script.md
```

with `ANTHROPIC_API_KEY` set, scripts are generated with AI. without it, you get a structured template to work from.

## security

this tool parses untrusted RSS/Atom feeds from the open internet lol, so a few things are hardened:

- XML parsing uses [defusedxml](https://github.com/tiran/defusedxml) to block XXE and billion laughs attacks
- TLS certificate verification is always enforced (never disabled)
- API calls sanitize exceptions to prevent key leakage in tracebacks
- no secrets are hardcoded, no user data is collected or stored
- no `eval`, `exec`, `subprocess`, or shell invocations
