# keylog-audit

A defensive, **read-only** tool that investigates possible keylogging
activity on **your own computer** by checking a small set of documented,
OS-level indicators — and, for every process it flags, explains exactly
which indicator fired and why.

## What this is NOT

- **Not a keylogger.** Nothing in this project captures, logs, records,
  or even reads a single keystroke, under any flag or configuration.
- **Not a keyboard hook, driver, or listener of any kind.**
- **Not a comprehensive keylogger detector.** It checks a small,
  specific, documented set of indicators. Many real keylogging
  techniques — kernel-mode drivers, hardware keyloggers plugged in
  between your keyboard and computer, browser extensions, and any
  technique that avoids every indicator this project checks — are
  **not detected by this tool at all**. See "Limitations" below.
- **Not something that modifies anything.** Every check here reads
  process metadata and permission/persistence locations a normal user
  account can already see (the same information Task Manager, Activity
  Monitor, or `ps` expose) — nothing is written, killed, or changed.

## What's realistically available, per OS — and why that shaped this project

Before writing any detection code, here's what a normal user account
can actually observe about running processes and keyboard access,
without needing administrator/root privileges beyond what a normal
desktop session already has:

| OS | Available without elevation | What it's used for here |
|---|---|---|
| **All three** | Process list: PID, name, path, command line, parent, owner, start time (via `psutil`, wrapping `/proc`, the Windows process APIs, and `sysctl`/`libproc` respectively) | `suspicious_path`, `name_masquerade`, `recent_executable` |
| **Linux** | `/proc/<pid>/fd/*` — which files/devices a process you own has open (root can see everyone's) | `linux_input_fd` — the single strongest, most direct indicator in this project: a process with an open handle to `/dev/input/eventN`, the raw keyboard device node |
| **Linux** | XDG autostart (`~/.config/autostart/`) and systemd user units (`~/.config/systemd/user/`) — both plain text, always readable | `linux_persistence` |
| **macOS** | LaunchAgents/LaunchDaemons `.plist` files — plain files, always readable | `macos_persistence` |
| **macOS** | TCC.db (records which apps were granted Input Monitoring/Accessibility — the permission macOS requires before an app can use low-level keyboard event-tap APIs) — **requires Full Disk Access**, a permission you must explicitly grant | `macos_tcc_input_permission` |
| **Windows** | `HKCU\...\Run`/`RunOnce` registry keys and the Startup folder — both readable by the owning user | `windows_persistence` |

What is **not** realistically available without much deeper, more
invasive access (kernel drivers, EDR-style callbacks, or tooling this
project deliberately doesn't build): a system-wide list of installed
`WH_KEYBOARD_LL` hooks on Windows, or a list of everything with an
active `CGEventTap` on macOS. This project does not attempt either —
see "Limitations".

## Setup

Requires Python 3.9+.

```bash
git clone <this-repo>
cd keylog-audit
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt        # psutil
pip install -r requirements-dev.txt    # only needed to run the tests
```

## Run it

```bash
# See the report format immediately, on ANY operating system —
# no real scan is performed:
python -m keylog_audit scan --sample-data

# Audit THIS machine for real:
python -m keylog_audit scan

# See which indicators can actually run on your OS, and why some can't:
python -m keylog_audit list-indicators

# Export the full report
python -m keylog_audit scan --output report.json
python -m keylog_audit scan --json-stdout --quiet | jq .

# Only show findings worth a closer look
python -m keylog_audit scan --min-confidence medium
```

## Permissions

- **A normal user account is enough for most of this project.** No step
  in the setup or normal usage requires `sudo`/administrator.
- **`linux_input_fd`** can only inspect processes you own — reading
  `/proc/<pid>/fd` for another user's process requires root. Running as
  root would let this specific check see every process, but this
  project does not ask you to, and doesn't need it to be useful: your
  own user session is exactly where a keylogger targeting you would be
  running.
- **`macos_tcc_input_permission`** requires granting the terminal (or
  whatever runs Python) **Full Disk Access** in System Settings >
  Privacy & Security. Without it, this one check reports "unavailable"
  — not a false "clear" — and the report says so explicitly.
- Every other check works with zero special permission at all.

## Supported operating systems

| OS | Status |
|---|---|
| Linux | Fully supported; every Linux-specific indicator implemented and tested |
| macOS | Implemented; `macos_persistence` works out of the box, `macos_tcc_input_permission` needs Full Disk Access (see above) |
| Windows | Implemented; requires Windows to actually run (uses the `winreg` standard-library module, which only exists there) |
| Anything else | The three cross-platform indicators (`suspicious_path`, `name_masquerade`, `recent_executable`) still run; OS-specific ones report "unavailable" |

**Use `--sample-data` to see the full report format and every indicator
type on any of these** — the sample mode fabricates a complete report
so the project can be demonstrated and reviewed without needing to run
it on all three operating systems.

## Reading a report

Every finding shows:
- The process (PID, name, path, owning user, start time)
- A **confidence level** (`low` / `medium` / `high`) — a transparent
  sum of each triggered indicator's documented weight against fixed,
  visible thresholds (see `scoring.py`) — never an opaque score.
- **Every indicator that fired**, each with its own plain-language
  reason and the literal evidence observed (a path, a registry value,
  an open file descriptor's target).

Confidence level is about how many independent, documented signals
co-occurred — **it is never a verdict**. Even "high" means "several
indicators lined up, a human should look at this," not "confirmed
keylogger." Run `python -m keylog_audit scan --sample-data` to see this
directly: the sample report's own "medium" example is a completely
legitimate remote-desktop tool.

## False positives

This matters enough to call out directly, with real examples:

- **`linux_input_fd`** flags *any* process reading a raw input device
  directly — which is exactly what legitimate remote-desktop/screen-sharing
  software, accessibility tools, some games, and macro utilities do.
  The bundled sample report includes exactly this scenario (a
  TeamViewer-like process) specifically so this isn't just a README
  caveat — it's in the tool's own output.
- **`suspicious_path`** flags plenty of entirely legitimate software:
  portable apps, some browser updaters, and anything a user
  deliberately runs from their Downloads folder.
- **`recent_executable`** flags literally anything installed or updated
  recently — which describes most software on an actively-used
  computer.
- **`name_masquerade`**'s absence of a match is not a guarantee either:
  it only checks a small, illustrative table of well-known process
  names (see `indicators/name_masquerade.py`) — most legitimate
  software isn't in that table at all, so it simply won't be
  evaluated by this specific check either way.

This is exactly why every finding reports *which* indicators fired
rather than a single score, and why the report's disclaimer says a
finding needs a human's manual review — this project is built to
narrow down what's worth a closer look, not to make the decision itself.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

**112 tests pass** (a 113th, live Windows registry access, only runs on
actual Windows and skips cleanly elsewhere). Highlights:

- Every indicator's matching logic is tested against fabricated,
  temporary filesystem/database fixtures (fake `/proc/<pid>/fd` trees,
  a real SQLite file shaped like TCC.db, fake `.desktop`/`.plist`
  files) — not just asserted in the abstract.
- Permission-denied paths are tested explicitly (`linux_input_fd`,
  `macos_tcc`) to confirm they degrade to "unavailable", never a false
  "clear" and never a crash.
- `windows_persistence`'s pure string-matching logic is tested on every
  OS (registry I/O is isolated behind an import guard); the one test
  that needs a real Windows registry is `skipif`'d elsewhere.
- `engine.py` is tested for OS-correct indicator gating, and for
  surviving a single indicator raising an exception on a single process
  without crashing the whole scan.
- `sample_data.py` is tested for being fully deterministic and for
  actually containing the high/medium/low/false-positive scenarios the
  README describes — not just asserted to "have some findings."

## Limitations — please read this before drawing any conclusion from a scan

- **This is not a comprehensive keylogger detector, and no "clean"
  result from this tool means a computer is free of keyloggers.**
  Techniques this project cannot see at all:
  - Kernel-mode drivers/rootkits that hide their own process
  - Hardware keyloggers (a physical device between keyboard and
    computer, or inside the keyboard itself) — nothing OS-visible at all
  - Browser extensions capturing form input
  - A keylogger built into otherwise-legitimate, signed, "normal-looking"
    software (masquerading only catches *name* mismatches, not
    intent)
  - Techniques specifically engineered to avoid every indicator listed
    above (e.g. hooking via a mechanism other than `/dev/input`,
    injecting into another process rather than running as its own)
- **Windows and macOS keyboard-hook enumeration is not implemented.**
  Listing every installed `WH_KEYBOARD_LL` hook system-wide, or every
  active `CGEventTap`, isn't realistically available to a normal user
  process without kernel-level access this project deliberately doesn't
  use — see the availability table above.
- **The reference tables (`name_masquerade`, `suspicious_path`) are
  small and illustrative, not exhaustive.** They're meant to catch
  obvious, common cases — a determined attacker can trivially avoid
  every substring/name match in this project.
- **The TCC schema is undocumented and has changed across macOS
  versions.** `macos_tcc.py`'s query is best-effort and wrapped so a
  schema mismatch degrades to "unavailable" rather than a wrong answer.
- **Scoring weights are illustrative, not empirically calibrated**
  against any real malware corpus — they encode "a direct hardware
  access indicator should outweigh a weak path heuristic," a defensible
  but ultimately judgment-based ordering, documented in `scoring.py`
  for anyone to inspect and disagree with.

## Portfolio description

> **keylog-audit** — A defensive, read-only Python tool that audits a
> user's own computer for documented, OS-level indicators possibly
> associated with keylogging activity, and explains exactly why each
> process was flagged rather than issuing a bare verdict. Implements
> real, tested indicators across three operating systems — including
> Linux's `/proc/<pid>/fd` scan for direct `/dev/input` access (the
> actual mechanism real evdev-based Linux keyloggers use) and macOS's
> TCC database query for Input Monitoring/Accessibility grants (the
> real permission gate Apple puts in front of keyboard event-tap APIs)
> — with a transparent, inspectable weight-based confidence score and a
> fabricated sample-data mode so the report format is demonstrable on
> any OS. Explicitly and repeatedly documents what it does NOT detect,
> rather than implying broader coverage than a process-metadata scanner
> can actually provide. 112 tests, largely against fabricated
> filesystem/database fixtures rather than assertions in the abstract.

**Technologies used:** Python 3, `psutil` (cross-platform process
introspection), `sqlite3` (macOS TCC database), `plistlib` (macOS
LaunchAgent/LaunchDaemon parsing, stdlib), `winreg` (Windows registry,
stdlib, import-guarded), `dataclasses`, `argparse`; `pytest` for
testing; `pyproject.toml`/`setuptools` for packaging.

**Demo suggestions:**
- `python -m keylog_audit scan --sample-data` — the fastest way to see
  the whole report format, including the high/medium/low tiers and the
  built-in false-positive example, on any machine.
- `python -m keylog_audit list-indicators` next to the "what's
  realistically available" table in this README — showing the tool's
  own self-reported capability list matches what's documented.
- A real `python -m keylog_audit scan` on your own machine — genuinely
  useful as a live demo since it's a real, working scan, not staged.
- `python -m pytest -v` passing, with the fabricated `/proc/<pid>/fd`
  and TCC.db fixtures specifically called out — most demos in this
  space assert behavior without actually exercising the OS-shaped
  logic against realistic fixtures.
- A short walkthrough of one finding end-to-end: the sample report's
  `svchost.exe`-in-AppData scenario, showing how four independent weak
  signals (masquerading, path, recency, persistence) combine into one
  "high confidence, please review this" result — the core idea the
  whole project is built around.

## License

MIT — see `LICENSE`.
