#!/usr/bin/env python3
"""Zero-token watch over the upstream submissions you are still waiting on.

Nothing here knows about any particular person or repository: the watch list, your own
login and the path to your token all live in a config file. Copy `config.example.json`,
edit it, done.

Runs as a no-agent cron tick: prints NOTHING when nothing happened (so nothing gets
delivered), prints one line per event when something did. The hard part is not finding
events — it is telling "quiet" apart from "broken", and that is what most of this file
is about.

Triggers, per object type:

  your PR    1. state is no longer open (a merge is reported first, with merged=true)
             2. a maintainer (OWNER/MEMBER/COLLABORATOR) responds
             3. a review asks for changes (CHANGES_REQUESTED)
  your issue 1. state is no longer open
             2. a maintainer responds
  others_activity   any comment or linked PR/commit from an account other than yours
             -> report. Once your PR is open, what changes your next action is the
             other side moving; them standing still is not news.
  claimer idle      count down from that account's OWN last action (comment, commit,
             linked PR). Your own comments never reset it. You are queued; their
             silence is the signal that the slot opened.

The rule both encode: claiming is not doing, and order is decided by public timestamps
only. So watch by position: with a PR open, watch the other side act; queued, watch the
other side not act.

A failed query is never rendered as a quiet one — every error path produces a message,
because a watcher that dies silently is worse than no watcher.

`--self-test` runs the whole decision logic against synthetic payloads. No network, no
config needed, no recorded real data.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MAINTAINERS = {"OWNER", "MEMBER", "COLLABORATOR"}
HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.json"

# Filled in by load_config(). Declared here so every function below can read them without
# threading a config object through twenty call sites.
CFG: dict = {}
OUR_LOGIN: str = ""
TARGETS: list = []
STATE: Path = HERE / "state" / "watch_targets.json"

# Timeline events that count as "somebody touched this issue from outside".
LINK_EVENTS = {"cross-referenced", "connected", "referenced", "committed"}

# What counts as an account ACTING, for the claimer countdown. Deliberately excluded:
# mentioned / subscribed / labeled / unlabeled / milestoned / locked — GitHub writes
# those on the account's behalf (a @-mention auto-subscribes you), so counting them
# would read a silent person as active. Found in the first live run on #41285.
ACTOR_ACTION_EVENTS = {
    "commented", "cross-referenced", "connected", "committed", "referenced",
    "reviewed", "merged", "closed", "reopened", "assigned", "unassigned",
    "head_ref_force_pushed", "renamed",
}

_ALL = {"state": True, "maintainer": True, "changes_requested": True}
_STATE_ONLY = {"state": True, "maintainer": False, "changes_requested": False}

# A maintainer can intervene without writing a single comment — a label, a review
# request, a milestone. 2026-10-21: the first real upstream intervention on any of
# our 16 objects was exactly this shape (a label added by the repo owner) and the
# watcher called it silent.
INTERVENE_EVENTS = {"labeled", "unlabeled", "assigned", "review_requested", "milestoned"}
REVIEW_LABEL = re.compile(r"reviewed|approved|lgtm", re.I)


def _privileged(login: str | None) -> bool:
    """Whether an account could act at all.

    Structural, not API-based: /repos/{r}/collaborators/{u}/permission returns 403 to
    outside contributors, but adding a label / assigning / setting a milestone /
    requesting a reviewer all require triage-or-better on the repo. So the existence
    of the event IS the proof of permission — no extra call, no guessing from comments.
    """
    return bool(login) and login != OUR_LOGIN


def event_key(e: dict):
    """Stable dedupe key for a timeline event.

    GitHub does NOT return `id` for every event type — recorded 2026-10-21 on a real
    payload: `cross-referenced` and `committed` come back with id=null, only `labeled`
    / `commented` carry one. Keying on the raw id silently dropped those events, so an
    id-less event that ever mattered would never be reported. Hash the identity fields
    instead; the fallback is stable across fetches.
    """
    eid = e.get("id")
    if eid is not None:
        return eid
    parts = [
        e.get("event"),
        (e.get("actor") or {}).get("login"),
        e.get("created_at"),
        (e.get("label") or {}).get("name"),
        ((e.get("source") or {}).get("issue") or {}).get("id"),
        e.get("commit_id"),
        (e.get("milestone") or {}).get("title"),
        (e.get("assignee") or {}).get("login"),
        (e.get("requested_reviewer") or {}).get("login"),
    ]
    return "h" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def maintainer_events(t: dict, events: list, seen: set, out: list, url: str) -> None:
    """Label / assign / review-request / milestone by a privileged account = 介入."""
    label = t["label"]
    for e in events or []:
        key = event_key(e)
        if key is None or key in seen:
            continue
        kind = e.get("event") or ""
        if kind not in INTERVENE_EVENTS:
            continue
        who = (e.get("actor") or {}).get("login")
        if not _privileged(who):
            continue
        if kind == "review_requested" and not (e.get("requested_reviewer") or {}).get("login"):
            continue                      # PR 创建时的自动事件，不是介入
        seen.add(key)
        bot = "🤖" if str(who).endswith("[bot]") else ""
        if kind in ("labeled", "unlabeled"):
            name = (e.get("label") or {}).get("name", "?")
            if REVIEW_LABEL.search(name):
                out.append(f"🏷️✅ {label} 维护者 @{who}{bot} 加了评审标签 `{name}` —— 已进评审流程。{url}")
            else:
                out.append(f"🏷️ {label} @{who}{bot} {kind} `{name}` —— {url}")
        elif kind == "assigned":
            out.append(f"👤 {label} @{who}{bot} 指派给 @{(e.get('assignee') or {}).get('login')} —— {url}")
        elif kind == "review_requested":
            out.append(
                f"👤 {label} @{who}{bot} 请求 @{(e.get('requested_reviewer') or {}).get('login')} 评审 —— {url}"
            )
        elif kind == "milestoned":
            out.append(f"🎯 {label} @{who}{bot} 加进 milestone `{(e.get('milestone') or {}).get('title')}` —— {url}")


def _t(line: str, repo: str, number: int, kind: str, label: str, desc: str, **extra) -> dict:
    d = {
        "key": f"{line.lower()}{number}",
        "line": line,
        "repo": repo,
        "number": number,
        "kind": kind,
        "label": f"{line} {label} {desc}".strip(),
        "triggers": dict(_ALL),
    }
    d.update(extra)
    return d


def _target(entry: dict) -> dict:
    """One watch target, built from one config entry.

      {"repo": "owner/name", "number": 123, "kind": "pr" | "issue",
       "line": "short tag repeated in every message (optional)",
       "desc": "what this submission is (optional)",
       "triggers": {"state": true, "maintainer": true, "changes_requested": true},
       "claimer": {"login": "someone", "days": 3},
       "others_activity": true,
       "on_closed_unmerged": "what this unlocks, appended to the close message"}

    Only repo/number/kind are required. `triggers` defaults to all three on, which is
    right for your own PR and wrong for your own issue (issues get no reviews) — say so
    explicitly rather than relying on the default.
    """
    repo = str(entry["repo"])
    number = int(entry["number"])
    kind = str(entry.get("kind", "pr"))
    if kind not in ("pr", "issue"):
        raise SystemExit(f"config: kind must be 'pr' or 'issue', got {kind!r} for {repo}#{number}")
    line = str(entry.get("line") or "")
    desc = str(entry.get("desc") or "")
    t = _t(line, repo, number, kind, f"#{number}", desc,
           triggers=dict(entry.get("triggers") or _ALL))
    # _t keys on line+number, which is enough for a person but collides between repos
    # when no line is set. Fall back to the repo name in that case.
    t["key"] = f"{line.lower()}{number}" if line else f"{repo.split('/')[-1].lower()}{number}"
    for opt in ("claimer", "others_activity", "on_closed_unmerged"):
        if entry.get(opt) is not None:
            t[opt] = entry[opt]
    return t


def load_config(path: str | Path | None = None) -> dict:
    """Read the watch list and the account it belongs to.

    Everything specific to one person lives in this file, not in the code: which
    repositories, which login counts as "us", where the token is, where the baseline is
    kept. That is what makes the script publishable without publishing somebody's
    submission history.
    """
    raw = path or os.environ.get("WATCH_UPSTREAM_CONFIG")
    p = Path(raw) if raw else DEFAULT_CONFIG
    if not p.exists():
        raise SystemExit(
            f"no config at {p}\n"
            "copy config.example.json to config.json, fill it in, or pass --config <path>"
        )
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"config {p} is not valid JSON: {e}") from None

    login = str(cfg.get("login") or "").strip()
    if not login:
        raise SystemExit(
            "config: `login` is required — without it every action by you would be "
            "reported as somebody else touching your submission"
        )

    global CFG, OUR_LOGIN, TARGETS, STATE
    CFG = cfg
    OUR_LOGIN = login
    base = p.parent
    STATE = base / str(cfg.get("state") or "state/watch_targets.json")
    entries = cfg.get("targets") or []
    if not isinstance(entries, list) or not entries:
        raise SystemExit(f"config: `targets` must be a non-empty list of objects")
    TARGETS = [_target(e) for e in entries]

    seen = set()
    for t in TARGETS:
        if t["key"] in seen:
            raise SystemExit(
                f"config: two targets share the key {t['key']!r} ({t['repo']}#{t['number']}); "
                "set `line` differently on one of them, or the two will overwrite each other's baseline"
            )
        seen.add(t["key"])
    return cfg


def token() -> str:
    """The GitHub token, from wherever the config says. Never printed, never logged."""
    src = CFG.get("token") or {}
    env = src.get("env")
    if env:
        value = os.environ.get(env, "").strip()
        if not value:
            raise SystemExit(f"config: token.env is {env!r} but that variable is empty")
        return value
    path = src.get("file")
    if not path:
        raise SystemExit('config: set token.env ("GITHUB_TOKEN") or token.file ("/path/to/token")')
    expanded = Path(os.path.expandvars(str(path))).expanduser()
    if not expanded.exists():
        raise SystemExit(f"config: token.file {expanded} does not exist")
    return expanded.read_text(encoding="utf-8").strip()


class TransientAPIError(Exception):
    """403 that carries rate-limit evidence: it passes by itself, so it must not page first."""


def classify_http_error(e: urllib.error.HTTPError) -> None:
    """Raise the right exception for a failed GitHub call. Always raises.

    403 has two meanings and only one is permanent. GitHub sends
    X-RateLimit-Remaining: 0 (or Retry-After) while it is throttling us; without those
    headers a 403 is a real permission problem and waiting will never fix it. Treating
    them the same either pages someone over a 60-second throttle or stays quiet on a
    broken token.
    """
    if e.code == 403:
        headers = e.headers or {}
        rem = headers.get("X-RateLimit-Remaining")
        retry = headers.get("Retry-After")
        if rem == "0" or retry is not None:
            raise TransientAPIError(
                f"HTTP 403 限流（X-RateLimit-Remaining={rem} Retry-After={retry}）"
            ) from None
    raise e


def api(path: str):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "token " + token(),
            "Accept": "application/vnd.github+json",
            "User-Agent": "upstream-watch",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        classify_http_error(e)


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    st: dict = {}
    # Optional: fold an older single-target baseline into the new one, so comments you
    # already read are not reported again when you move to this tool.
    imp = CFG.get("import_state") or {}
    if imp.get("file") and imp.get("key"):
        try:
            legacy = json.loads((STATE.parent.parent / str(imp["file"])).read_text(encoding="utf-8"))
            st[str(imp["key"])] = {
                "state": legacy.get("state", "open"),
                "merged": bool(legacy.get("merged", False)),
                "assignees": legacy.get("assignees", []),
                "seen_ids": legacy.get("seen_comment_ids", legacy.get("seen_ids", [])),
            }
        except Exception:
            pass
    return st


def save_state(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, ensure_ascii=False, indent=2), encoding="utf-8")


def _dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def claimer_idle(t: dict, obj: dict, comments: list, events: list, prev: dict, now):
    """「认领人本人 N 天没有动作」判据 → (message | None, dedupe_key | None).

    Only that account's own actions count. Our comments never reset the clock —
    we are queued behind them, and our own activity is not news about them.
    """
    spec = t.get("claimer")
    if not spec or obj.get("state") != "open":
        return None, None
    who, days = spec["login"], spec.get("days", 3)

    acts = []
    for c in comments:
        if (c.get("user") or {}).get("login") == who:
            when = _dt(c.get("created_at"))
            if when:
                acts.append((when, "他的评论"))
    for e in events or []:
        if (e.get("actor") or {}).get("login") != who:
            continue
        if (e.get("event") or "") not in ACTOR_ACTION_EVENTS:
            continue
        when = _dt(e.get("created_at"))
        if when:
            acts.append((when, f"他的 {e.get('event')}"))
    if not acts:
        return None, None          # 没有任何他本人的动作 → 没有起点，不凭空计时
    last_when, last_what = max(acts)

    idle = (now - last_when).total_seconds() / 86400
    if idle < days:
        return None, None
    key = f"{who}@{last_when.strftime('%Y-%m-%dT%H:%MZ')}"
    if prev.get("claimer_idle_alerted") == key:
        return None, key           # 同一段沉默只报一次；他有新动作后重新计时
    url = f"https://github.com/{t['repo']}/issues/{t['number']}"
    msg = (
        f"🕒 {t['label']} 认领人 @{who} 最后一次动作是 {last_when.strftime('%Y-%m-%dT%H:%MZ')}"
        f"（{last_what}），此后 {idle:.1f} 天他本人没有任何评论/提交/PR —— "
        f"我们在排队，这是入场信号。{url}"
    )
    return msg, key


def others_activity(t: dict, comments: list, events: list, seen: set, out: list) -> None:
    """任何非我们账号的评论或关联 PR/commit → 报。用于我们已经开出 PR 的对象。"""
    label = t["label"]
    url = f"https://github.com/{t['repo']}/issues/{t['number']}"
    for c in comments:
        cid = c.get("id")
        if cid is None or cid in seen:
            continue
        who = (c.get("user") or {}).get("login")
        if who and who != OUR_LOGIN:
            body = " ".join((c.get("body") or "").split())[:200]
            assoc = c.get("author_association") or "NONE"
            out.append(f"‼️ {label} @{who}（{assoc}）评论：{body} —— {c.get('html_url', url)}")
        seen.add(cid)
    for e in events or []:
        key = event_key(e)
        if key is None or key in seen:
            continue
        if (e.get("event") or "") in LINK_EVENTS:
            who = (e.get("actor") or {}).get("login")
            if who and who != OUR_LOGIN:
                src = e.get("source") or {}
                what = ((src.get("issue") or {}).get("title") or src.get("type") or "")
                out.append(
                    f"‼️ {label} @{who} 关联了 {e.get('event')}：{str(what)[:120]} —— "
                    f"{url}#event-{key}"
                )
        seen.add(key)


def evaluate(t: dict, obj: dict, comments: list, reviews: list, prev: dict,
             events: list | None = None, now=None) -> tuple[list[str], dict]:
    """Pure decision function: (messages, new_state). Exercised by --self-test."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    label = t["label"]
    url = f"https://github.com/{t['repo']}/{('pull' if t['kind'] == 'pr' else 'issues')}/{t['number']}"
    trg = t.get("triggers") or dict(_ALL)
    if t["kind"] == "issue":
        trg = dict(trg, changes_requested=False)
    seen = set(prev.get("seen_ids", []))
    out: list[str] = []

    state = obj.get("state")
    merged = bool(obj.get("merged"))

    if trg.get("state", True):
        if merged and not prev.get("merged"):
            out.append(
                f"🟢 {label} 已合并（merged=true, merged_at={obj.get('merged_at')}）—— 合并凭证，去核。{url}"
            )
        elif state != "open" and prev.get("state") == "open":
            line = (
                f"‼️ {label} 状态变成 {state}（merged={str(merged).lower()}, "
                f"state_reason={obj.get('state_reason')}）"
            )
            if not merged and t.get("on_closed_unmerged"):
                line += f" —— {t['on_closed_unmerged']}"
            out.append(f"{line}。{url}")

    assignees = sorted(a["login"] for a in obj.get("assignees") or [])
    if t["kind"] == "issue" and assignees and assignees != sorted(prev.get("assignees", [])):
        out.append(f"‼️ {label} 已指派给 @{', @'.join(assignees)} —— 看是不是我们。{url}")

    if t.get("others_activity"):
        others_activity(t, comments, events or [], seen, out)
    else:
        for c in comments:
            cid = c.get("id")
            if cid is None or cid in seen:
                continue
            if trg.get("maintainer", True) and (c.get("author_association") or "").upper() in MAINTAINERS:
                body = " ".join((c.get("body") or "").split())[:200]
                out.append(f"‼️ {label} 维护者 @{c['user']['login']} 回应：{body} —— {c.get('html_url', url)}")
            seen.add(cid)

    for r in reviews:
        rid = r.get("id")
        if rid is None or rid in seen:
            continue
        st = (r.get("state") or "").upper()
        if trg.get("maintainer", True) and st in ("APPROVED", "COMMENTED"):
            body = " ".join((r.get("body") or "").split())[:200]
            who = (r.get("user") or {}).get("login", "?")
            icon = "✅" if st == "APPROVED" else "💬"
            out.append(f"{icon} {label} 维护者评审 {st}（@{who}）：{body or '(无正文)'} —— {r.get('html_url', url)}")
        elif trg.get("changes_requested", True) and st == "CHANGES_REQUESTED":
            body = " ".join((r.get("body") or "").split())[:200]
            who = (r.get("user") or {}).get("login", "?")
            out.append(f"‼️ {label} 要求修改（@{who}）：{body} —— {r.get('html_url', url)}")
        seen.add(rid)

    if trg.get("maintainer", True):
        maintainer_events(t, events or [], seen, out, url)

    idle_msg, idle_key = claimer_idle(t, obj, comments, events or [], prev, now)
    if idle_msg:
        out.append(idle_msg)

    new = {
        "state": state,
        "merged": merged,
        "assignees": assignees,
        "seen_ids": sorted((x for x in seen if x is not None), key=str),
    }
    if idle_key is not None:
        new["claimer_idle_alerted"] = idle_key
    elif prev.get("claimer_idle_alerted"):
        new["claimer_idle_alerted"] = prev["claimer_idle_alerted"]
    return out, new


def collect(t: dict) -> tuple[dict, list, list, list]:
    repo, n = t["repo"], t["number"]
    obj = api(f"/repos/{repo}/{('pulls' if t['kind'] == 'pr' else 'issues')}/{n}")
    comments = api(f"/repos/{repo}/issues/{n}/comments?per_page=100")
    reviews = api(f"/repos/{repo}/pulls/{n}/reviews?per_page=100") if t["kind"] == "pr" else []
    events = api(f"/repos/{repo}/issues/{n}/timeline?per_page=100")
    return obj, comments, reviews, events


def error_message(label: str, exc: Exception, streak: int | None) -> str:
    """A failed query must never look like a quiet one.

    Returns the message to send. Kept as its own function so the self-test can drive
    the exact text the cron path produces, not a paraphrase of it.
    """
    if isinstance(exc, urllib.error.HTTPError):
        detail = f"GitHub API {exc.code} {exc.reason}"
        hint = ""
        if exc.code in (401, 403):
            rem = (exc.headers or {}).get("X-RateLimit-Remaining")
            hint = f"（X-RateLimit-Remaining={rem}，0 就是额度用完）"
        extra = f" —— {detail}{hint}"
    else:
        extra = f" —— {type(exc).__name__}: {exc}"
    tail = f"，连续第 {streak} 次" if streak else ""
    return f"‼️ {label} 盯梢取数失败{tail}{extra}。这不是「没有动静」，基线未更新，请看一眼。"


def main() -> int:
    argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()

    cfg_path = None
    if "--config" in argv:
        i = argv.index("--config")
        if i + 1 >= len(argv):
            raise SystemExit("--config needs a path")
        cfg_path = argv[i + 1]
    load_config(cfg_path)

    st = load_state()
    streaks: dict = st.setdefault("_err_streak", {})
    messages: list[str] = []
    changed = False
    for t in TARGETS:
        try:
            obj, comments, reviews, events = collect(t)
        except TransientAPIError as e:
            n = int(streaks.get(t["key"], 0)) + 1
            streaks[t["key"]] = n
            changed = True
            # Simon 10-24: 限流也算事件。两次才报等于"坏掉的哨兵看起来像安静"，
            # 宁可每小时被吵一次，也不要它静默失灵。
            messages.append(error_message(t["label"], e, n))
            continue
        except urllib.error.HTTPError as e:
            messages.append(error_message(t["label"], e, None))
            continue
        except Exception as e:  # noqa: BLE001
            messages.append(f"‼️ {t['label']} 盯梢取数失败：{type(e).__name__}: {e} —— 不是「没有动静」，基线未更新。")
            continue
        if streaks.pop(t["key"], None) is not None:
            changed = True
            messages.append(f"✅ {t['label']} 盯梢恢复取数（之前是失败，已重新对上基线）。")
        prev = st.get(t["key"])
        if prev is None:
            # First sight of this object: seed silently. Old comments/reviews/assignees
            # must not re-report, but a state that is already not-open still reports.
            prev = {
                "state": "open",
                "merged": False,
                "assignees": sorted(a["login"] for a in obj.get("assignees") or []),
                "seen_ids": sorted(
                    [c["id"] for c in comments if c.get("id") is not None]
                    + [r["id"] for r in reviews if r.get("id") is not None]
                    + [k for k in (event_key(e) for e in events) if k is not None],
                    key=str,
                ),
            }
        out, new = evaluate(t, obj, comments, reviews, prev, events)
        messages.extend(out)
        if new != st.get(t["key"]):
            st[t["key"]] = new
            changed = True

    if messages:
        print("\n".join(messages))
        st["last_report"] = datetime.datetime.now().isoformat(timespec="seconds")
        changed = True
    known = {t["key"] for t in TARGETS}
    for stale in [k for k in st if k not in known and k not in ("last_report", "_err_streak")]:
        st.pop(stale, None)          # 改过 key 的旧条目，留着只会挡住新目标的首次播种
        changed = True
    if changed:
        save_state(st)
    return 0


def case(name: str, ok: bool, out: list | None = None) -> int:
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok or not out else f" -> {out}"))
    case.total += 1
    return 0 if ok else 1


case.total = 0


def self_test() -> int:
    """Every decision the tool makes, driven by synthetic payloads.

    No network, no config, no recorded real data — so this runs on a fresh clone and
    cannot leak anybody's submission history. Each case states the rule it pins down;
    if a change makes one fail, the rule it names is what broke.
    """
    global OUR_LOGIN
    OUR_LOGIN = "self-demo"

    t_pr = _t("X", "acme/widget", 101, "pr", "#101", "our open PR")
    t_issue = _t("X", "acme/widget", 102, "issue", "#102", "our open issue")
    t_state = _t("X", "acme/widget", 103, "pr", "#103", "state only",
                 triggers=dict(_STATE_ONLY), on_closed_unmerged="unlocks the follow-up")
    t_others = _t("X", "acme/widget", 104, "issue", "#104", "other side moving", others_activity=True)
    t_claim = _t("X", "acme/widget", 105, "issue", "#105", "queued",
                 claimer={"login": "claimer-demo", "days": 3})

    open_ = {"state": "open", "merged": False, "merged_at": None, "assignees": [], "state_reason": None}
    prev = {"state": "open", "merged": False, "assignees": [], "seen_ids": [1]}
    old = {"id": 1, "author_association": "NONE", "user": {"login": "someone"}, "body": "old",
           "created_at": "2026-10-01T00:00:00Z"}
    maint = {"id": 2, "author_association": "MEMBER", "user": {"login": "maintainer"},
             "body": "looking now", "created_at": "2026-10-20T00:00:00Z"}
    review = [{"id": 9, "state": "CHANGES_REQUESTED", "user": {"login": "rev"}, "body": "please split"}]
    fails = 0

    # --- your own PR: three triggers, and only three ---
    out, _ = evaluate(t_pr, open_, [old], [], prev)
    fails += case("own PR, nothing new -> silent", out == [], out)

    out, _ = evaluate(t_pr, open_, [old, maint], [], prev)
    fails += case("own PR, maintainer replies -> reports", any("maintainer" in m for m in out), out)

    out, _ = evaluate(t_pr, open_, [old], review, prev)
    fails += case("own PR, changes requested -> reports", any("要求修改" in m for m in out), out)

    out, _ = evaluate(t_pr, dict(open_, state="closed", merged=True, merged_at="2026-10-22T00:00:00Z"), [old], [], prev)
    fails += case("own PR merged -> reports with merged=true",
                  len(out) == 1 and "已合并" in out[0] and "merged=true" in out[0], out)

    out, _ = evaluate(t_pr, dict(open_, state="closed"), [old], [], prev)
    fails += case("own PR closed unmerged -> reports with merged=false",
                  len(out) == 1 and "merged=false" in out[0], out)

    out, _ = evaluate(t_pr, open_, [old], review, dict(prev, seen_ids=[1, 9]))
    fails += case("an event already in the baseline is not reported twice", out == [], out)

    # --- your own issue: no reviews to wait for ---
    out, _ = evaluate(t_issue, open_, [old, maint], [], prev)
    fails += case("own issue, maintainer replies -> reports", any("maintainer" in m for m in out), out)

    out, _ = evaluate(t_issue, dict(open_, state="closed"), [old], [], prev)
    fails += case("own issue closed -> reports", any("状态变成 closed" in m for m in out), out)

    out, _ = evaluate(t_issue, open_, [old], review, prev)
    fails += case("own issue, a review changes nothing (issues get no reviews)", out == [], out)

    out, _ = evaluate(t_issue, dict(open_, assignees=[{"login": "somebody"}]), [old], [], prev)
    fails += case("own issue assigned to someone else -> says so", any("已指派给 @somebody" in m for m in out), out)

    out, _ = evaluate(t_issue, dict(open_, assignees=[{"login": "somebody"}]), [old], [],
                      dict(prev, assignees=["somebody"]))
    fails += case("an unchanged assignee is not news", out == [], out)

    # --- state-only: the whole point is that a comment does NOT count ---
    prev_state = {"state": "open", "merged": False, "assignees": [], "seen_ids": []}
    out, _ = evaluate(t_state, dict(open_, state="closed"), [], [], prev_state)
    fails += case("state-only, closed unmerged -> reports and names what it unlocks",
                  len(out) == 1 and "merged=false" in out[0] and "unlocks the follow-up" in out[0], out)

    out, _ = evaluate(t_state, dict(open_, state="closed", merged=True, merged_at="2026-10-22T00:00:00Z"), [], [], prev_state)
    fails += case("state-only, merged -> reports the merge, not the unlock",
                  len(out) == 1 and "merged=true" in out[0] and "unlocks the follow-up" not in out[0], out)

    out, _ = evaluate(t_state, open_, [dict(maint, id=77)], [], prev_state)
    fails += case("state-only, maintainer comment -> silent", out == [], out)

    # --- others_activity: your PR is open, so what matters is the other side moving ---
    now = datetime.datetime(2026, 10, 21, 12, 0, tzinfo=datetime.timezone.utc)
    mine = {"id": 601, "author_association": "OWNER", "user": {"login": "self-demo"},
            "body": "patch ready, PR open", "created_at": "2026-10-20T14:16:00Z"}
    theirs = {"id": 602, "author_association": "NONE", "user": {"login": "claimer-demo"},
              "body": "still on it, will open a PR", "created_at": "2026-10-21T09:00:00Z"}
    xref = {"id": 700, "event": "cross-referenced", "actor": {"login": "third-party"},
            "created_at": "2026-10-21T09:30:00Z",
            "source": {"issue": {"title": "fix: don't stack client retries"}}}
    prev_ours = {"state": "open", "merged": False, "assignees": [], "seen_ids": [601, 700]}

    out, _ = evaluate(t_others, open_, [mine], [], prev_ours, [xref], now)
    fails += case("others_activity: only your own comment -> silent", out == [], out)

    out, _ = evaluate(t_others, open_, [mine, theirs], [], prev_ours, [], now)
    fails += case("others_activity: the other account comments -> reports them",
                  len(out) == 1 and "@claimer-demo" in out[0], out)

    out, _ = evaluate(t_others, open_, [mine], [], dict(prev_ours, seen_ids=[601]), [xref], now)
    fails += case("others_activity: a third party links a PR -> reports",
                  any("关联了 cross-referenced" in m for m in out), out)

    out, new_ours = evaluate(t_others, open_, [mine, theirs], [], prev_ours, [xref], now)
    again = evaluate(t_others, open_, [mine, theirs], [], new_ours, [xref], now)[0]
    fails += case("others_activity: re-running on the returned baseline is silent", again == [], again)

    # --- claimer idle: their own silence is the entry signal ---
    kyl_claim = {"id": 801, "author_association": "NONE", "user": {"login": "claimer-demo"},
                 "body": "I'd like to work on this", "created_at": "2026-10-17T11:21:00Z"}
    ours_after = {"id": 802, "author_association": "NONE", "user": {"login": "self-demo"},
                  "body": "patch ready, waiting to be assigned", "created_at": "2026-10-20T15:08:00Z"}
    prev_claim = {"state": "open", "merged": False, "assignees": [], "seen_ids": [801, 802]}

    out, new_claim = evaluate(t_claim, open_, [kyl_claim, ours_after], [], prev_claim, [], now)
    fails += case("claimer idle 4.0 days, our own comment does not reset it -> reports",
                  len(out) == 1 and "@claimer-demo" in out[0] and "入场信号" in out[0], out)
    again = evaluate(t_claim, open_, [kyl_claim, ours_after], [], new_claim, [], now)[0]
    fails += case("claimer idle: the same stretch of silence is reported once",
                  new_claim.get("claimer_idle_alerted", "").startswith("claimer-demo@") and again == [], again)

    fresh = {"id": 803, "author_association": "NONE", "user": {"login": "claimer-demo"},
             "body": "still working, ETA tomorrow", "created_at": "2026-10-20T12:00:00Z"}
    out, _ = evaluate(t_claim, open_, [kyl_claim, fresh], [], prev_claim, [], now)
    fails += case("claimer idle: they acted 0.5 days ago -> silent", out == [], out)

    soon = datetime.datetime(2026, 10, 19, 12, 0, tzinfo=datetime.timezone.utc)
    out, _ = evaluate(t_claim, open_, [kyl_claim], [], prev_claim, [], soon)
    fails += case("claimer idle: only 1.5 days -> silent, the threshold is 3", out == [], out)

    # GitHub writes mentioned/subscribed on your behalf when somebody @-mentions you.
    # Counting those as action is what made the first live run stay silent.
    passive = [
        {"id": 900, "event": "mentioned", "actor": {"login": "claimer-demo"}, "created_at": "2026-10-20T15:11:16Z"},
        {"id": 901, "event": "subscribed", "actor": {"login": "claimer-demo"}, "created_at": "2026-10-20T15:11:16Z"},
        {"id": 902, "event": "labeled", "actor": {"login": "claimer-demo"}, "created_at": "2026-10-20T16:00:00Z"},
    ]
    out, _ = evaluate(t_claim, open_, [kyl_claim], [],
                      dict(prev_claim, seen_ids=[801, 802, 900, 901, 902]), passive, now)
    fails += case("claimer idle: mentioned/subscribed are not actions -> still counts from their last real one",
                  len(out) == 1 and "2026-10-17T11:21" in out[0], out)

    # --- regression: a maintainer can intervene without writing a word ---
    # A label applied by someone with triage permission IS the proof they looked at it.
    # This fired on the first real upstream intervention we ever got, and the watcher
    # called it silence.
    label_ev = {"id": 1500, "event": "labeled", "actor": {"login": "maintainer"},
                "created_at": "2026-10-20T18:30:00Z", "label": {"name": "ci-reviewed"}}
    out, _ = evaluate(t_pr, open_, [old], [], prev, [label_ev], now)
    fails += case("a maintainer adds a review label -> reported, with the label named",
                  any("ci-reviewed" in m and "maintainer" in m for m in out), out)

    # --- regression: GitHub returns id=null for cross-referenced / committed ---
    # Keying dedupe on the raw id dropped those events entirely, so an id-less event
    # that ever mattered would never be reported. It must fire once, then stay quiet.
    noid = dict(label_ev, id=None)
    out2, new2 = evaluate(t_pr, open_, [old], [], prev, [noid], now)
    again2 = evaluate(t_pr, open_, [old], [], new2, [noid], now)[0]
    fails += case("an id-less event is reported once and not repeated",
                  sum(1 for m in out2 if "ci-reviewed" in m) == 1 and again2 == [], [out2, again2])

    # --- 403 has two meanings, and only one of them is worth waiting for ---
    def http_error(code, headers):
        return urllib.error.HTTPError("https://api.github.com/x", code, "err", dict(headers), None)

    def classify(e):
        try:
            classify_http_error(e)
        except TransientAPIError:
            return "transient"
        except urllib.error.HTTPError:
            return "hard"
        return None

    fails += case("403 with X-RateLimit-Remaining: 0 -> transient throttle",
                  classify(http_error(403, {"X-RateLimit-Remaining": "0"})) == "transient")
    fails += case("403 with Retry-After -> transient throttle",
                  classify(http_error(403, {"Retry-After": "60"})) == "transient")
    fails += case("403 without rate-limit headers -> a real permission problem",
                  classify(http_error(403, {})) == "hard")
    fails += case("401 and 404 -> always a real problem",
                  classify(http_error(401, {})) == "hard" and classify(http_error(404, {})) == "hard")

    # --- classifying right is not the same as saying something ---
    m1 = error_message("#101", http_error(403, {"X-RateLimit-Remaining": "0"}), 1)
    fails += case("a throttle produces a message that names the budget and denies it is quiet",
                  bool(m1) and "X-RateLimit-Remaining=0" in m1 and "不是「没有动静」" in m1, [m1])
    m2 = error_message("#101", TransientAPIError("HTTP 403 限流（X-RateLimit-Remaining=0 Retry-After=60）"), 1)
    fails += case("a throttle is reported the first time, not the second",
                  "盯梢取数失败" in m2 and "连续第 1 次" in m2, [m2])
    m3 = error_message("#101", ConnectionResetError("connection reset by peer"), None)
    fails += case("a network error produces a message too, never silence",
                  "ConnectionResetError" in m3 and "不是「没有动静」" in m3, [m3])

    # --- the config surface: the parts a new user will get wrong ---
    def cfg_fails(payload: dict) -> str:
        """Write a config, try to load it, return the SystemExit text ('' if it loaded)."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            try:
                load_config(path)
            except SystemExit as e:
                return str(e)
            except Exception as e:  # noqa: BLE001
                return f"unexpected {type(e).__name__}: {e}"
        return ""

    fails += case("config without `login` is refused, not silently guessed",
                  "login" in cfg_fails({"targets": [{"repo": "a/b", "number": 1}]}))
    fails += case("config without targets is refused",
                  "targets" in cfg_fails({"login": "self-demo", "targets": []}))
    fails += case("two targets sharing a key are refused, not silently overwritten",
                  "share the key" in cfg_fails({"login": "self-demo", "targets": [
                      {"repo": "a/b", "number": 7, "line": "X"},
                      {"repo": "c/d", "number": 7, "line": "X"}]}))
    fails += case("a bad `kind` is refused with the object named",
                  "kind must be" in cfg_fails({"login": "self-demo", "targets": [
                      {"repo": "a/b", "number": 7, "kind": "issue-ish"}]}))

    def cfg_loads(payload: dict):
        """Load a config from a temp dir and return the globals it set."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            load_config(path)
            return OUR_LOGIN, [t["key"] for t in TARGETS], str(STATE), [t["kind"] for t in TARGETS]

    got_login, got_keys, got_state, got_kinds = cfg_loads(
        {"login": "self-demo", "targets": [{"repo": "a/b", "number": 7, "kind": "issue"}]})
    fails += case("a minimal config sets the login, one key, and a state path",
                  got_login == "self-demo" and got_keys == ["b7"] and got_state.endswith("watch_targets.json"),
                  [got_login, got_keys, got_state])

    got_login, got_keys, _, got_kinds = cfg_loads({"login": "self-demo", "targets": [
        {"repo": "a/b", "number": 7, "line": "D"}, {"repo": "c/d", "number": 9, "kind": "issue"}]})
    fails += case("keys fall back to the repo name when no `line` is set",
                  got_keys == ["d7", "d9"], got_keys)

    total = case.total
    print(f"self-test: {total - fails}/{total} ok")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
