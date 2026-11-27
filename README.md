# LogAnalyzerAgent

Finds SSH brute-force attempts in server logs by asking Claude to read each log
line and pull out the useful bits (IP address, username, what happened).

This is the AI version of [LogAnalyzer](../LogAnalyzer), which does the same job
with regular expressions. The regex version is free and instant; this one is
slower and costs a little, but it can handle log lines nobody wrote a pattern
for.

## What it does

1. Reads log lines from `data/OpenSSH_2k.log_structured.csv`
2. Sends each one to Claude, which returns structured fields
3. Saves them to a SQLite database (`ssh_logs.db`)
4. Counts failed logins per IP and flags the noisy ones

## Setup

You need Python 3.11+ and an Anthropic API key.

```bash
uv sync
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

## Run

```bash
uv run main.py
```

It processes the first 50 log lines (about a minute) and prints:

```
Brute force suspects: 2
112.95.230.3: 11 attempts
173.234.31.186: 6 attempts
```

To change how much it reads or how strict it is, edit the bottom of `main.py`.

Note: re-running adds to the database instead of replacing it. To start fresh:

```bash
sqlite3 ssh_logs.db "DELETE FROM ssh_logs;"
```

## Ideas for improvement

- **Only count real attempts.** One failed login writes two log lines, so the
  counts above are roughly double what they should be.
- **Add a time window.** "5 failures in 10 minutes" is a much better signal than
  "5 failures ever". LogAnalyzer already does this.
- **Save the date.** Right now only the time is stored, so days can't be told
  apart.
- **Make it cheaper.** Most log lines repeat — 63% of this file is duplicates.
  Skipping repeats would cut the API calls by more than half.
- **Make it faster.** The lines are sent one at a time; sending several at once
  or in parallel would speed things up a lot.
- **Handle errors.** If one API call fails, the whole run stops.
