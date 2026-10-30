# upstream-watch

A cron-friendly watcher for pull requests and issues you are waiting on. It prints **nothing** when nothing happened, and one line per event when something did — so the only thing it can deliver to your phone is news.

Single file. Standard library only. No dependencies, no daemon, no database.

## The problem it solves

If you contribute upstream, you spend weeks in a state that has no notification: *my PR is open and nobody has said anything*. GitHub will not tell you, because nothing happened. So you check manually, or you forget, and a maintainer's question sits unanswered for three days.

But the naive fix — poll the API and print changes — fails in the opposite direction. A watcher that crashes, gets rate-limited, or has an expired token prints nothing too. **"Nothing happened" and "I am broken" look identical.** Most of this file exists to keep those two apart.

## How it decides

You tell it which position you are in, and it watches the right thing:

| Position | Watcher mode | Reports when |
|---|---|---|
| Your PR is open | default | state changes, a maintainer replies, or a review asks for changes |
| Your issue is open | default | state changes, or a maintainer replies |
| Someone else claimed it and your PR is already open | `others_activity` | **they** act — a comment, a linked PR, a commit. Their stillness is not news; you already moved |
| You are queued behind a claim | `claimer` | the claimer has taken no action of their own for N days — that silence is your entry signal |

Two rules hide inside that table:

- **Claiming is not doing.** Order is decided by public timestamps, so the only thing that counts as the other person acting is a comment, a commit, a review, or a linked PR. `mentioned`, `subscribed`, `labeled` and friends are excluded: GitHub writes those *on your behalf* when somebody @-mentions you, and counting them reads a silent person as active. That exact bug made the first live run of this tool stay quiet when it should have fired.
- **A maintainer can intervene without writing a word.** Adding a label, assigning someone, requesting a reviewer, or setting a milestone all require triage permission — so the *existence* of that event is proof someone with authority looked at it. Treating labels as silence missed the first real upstream response this tool was built to catch.

### Telling "quiet" from "broken"

- Every failure path produces a message. There is no code path where an error ends in no output.
- A 403 with rate-limit headers is a throttle and passes by itself; a 403 without them is a permissions problem and waiting will never fix it. They are routed differently on purpose.
- A throttle is reported on the **first** occurrence, not the second. Two consecutive failures before saying anything is how a sentinel goes silent while looking healthy.
- Recovery is announced too, so a flapping watcher is visible rather than self-healing invisibly.
- Every reported event is written to a baseline file, so the same event never fires twice — and a first run seeds the baseline silently, so installing it does not dump a year of history into your terminal.

## Install

Requires Python 3.10+ (it uses `X | None` annotations). No packages to install.

```bash
git clone https://github.com/simin-yuan/upstream-watch.git && cd upstream-watch
cp config.example.json config.json
$EDITOR config.json                      # your login, your targets, your token path
python watch_upstream.py --self-test     # 38 checks, no network
python watch_upstream.py                 # dry run against the real API
```

The token needs no scopes for public repositories. Put it where `config.token` points:

```json
"token": {"env": "GITHUB_TOKEN"}
```
```json
"token": {"file": "~/.config/upstream-watch/token"}
```

## Config

```json
{
  "login": "your-github-login",
  "token": {"env": "GITHUB_TOKEN"},
  "state": "state/watch_targets.json",
  "targets": [
    {"repo": "acme/widget", "number": 1234, "kind": "pr", "line": "A",
     "desc": "fix truncated tool-call args"},
    {"repo": "acme/widget", "number": 88, "kind": "issue", "line": "B",
     "others_activity": true},
    {"repo": "third-org/tool", "number": 501, "kind": "issue", "line": "C",
     "claimer": {"login": "the-claimer", "days": 3}}
  ]
}
```

`repo`, `number`, `kind` are required. The rest:

| key | meaning |
|---|---|
| `login` (top level) | **required.** Your account. Without it, every action of yours would be reported as somebody else touching your submission |
| `line` | short tag repeated in every message, so a phone notification says which thread it is |
| `desc` | what the submission is, for your own benefit |
| `triggers` | `{"state", "maintainer", "changes_requested"}`; defaults to all true. Set `changes_requested: false` on issues — they get no reviews |
| `others_activity` | report anything done by an account that is not you |
| `claimer` | `{"login": ..., "days": N}` — report when they have been still for N days |
| `on_closed_unmerged` | text appended when it closes without merging, for "if this dies, my next move is X" |

Config is validated on load: a missing login, an empty target list, two targets sharing a key, or an unknown `kind` all stop with a message naming the offender. Silent misconfiguration is the failure mode worth refusing.

## Running it on a schedule

```cron
0 10,22 * * *  cd /opt/upstream-watch && GITHUB_TOKEN=... python watch_upstream.py
```

Deliberately not every minute: nobody merges your PR within one minute of it being opened, and each poll spends API budget you may want later. Twice a day is enough for a maintainer thread; use `*/15` only for something genuinely time-sensitive, and remember the request budget is per hour.

`--self-test` exits 0 when every rule holds, non-zero otherwise, and prints one line per rule. It needs no config, no token and no network: all payloads are synthetic, so it runs on a fresh clone and cannot leak anyone's submission history.

## Translating the output

The notification strings are in Chinese, because that is where this started. They are the part most worth changing for your own use, and `--self-test` asserts on several of them, so change the strings **and** the matching assertions together or the suite will tell you — loudly, which is the point.

The strings live in five places: `maintainer_events`, `claimer_idle`, `others_activity`, `evaluate`, and `error_message`.

## Known limits

- Polls the REST API once per target per run. There is no ETag caching, so a hundred targets is a hundred requests per tick.
- No notification transport of its own: it prints. Whatever runs it decides where the text goes, which is what keeps it usable from cron, a systemd timer, or an agent.
- The claimer countdown assumes "days" means calendar days of silence, and uses the account's own last action. It does not know whether the claimer is on holiday.
- Dedupe state is a single JSON file. Two runs at the same time on the same file will race; it is not built for that.
- A personal tool, maintained on a best-effort basis; no response-time commitment.

## Deliberately public strings

`tools/leak_scan.py` refuses to push when it finds a machine path, a credential, an e-mail
address, a private-network address, or any term in your local `.leak_patterns`.

Attribution is the exception. `.leak_allow` (gitignored) lists literal strings that are
public on purpose — your name on a copyright line, the project's own URL. A deny-list hit is
dropped only when the *same line* also contains one of those strings, so `Copyright (c) 2026
Simin Yuan` passes while a bare handle or a private term on any other line still blocks it.

## License

MIT. See [LICENSE](LICENSE) — one paragraph, no patent language, nothing to read. If this
repository ever accepts contributions from companies, switch to Apache-2.0 *before* that happens
rather than after: relicensing needs consent from every past contributor.
