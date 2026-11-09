#!/usr/bin/env python3
"""
qualys_report_fetch.py - generate and download Qualys VM scan reports automatically.

For each selected client:
  1. List the client's scans that finished in the lookback window and haven't been
     processed yet (Qualys filters by Client server-side)
  2. Sort each scan into a scan type (e.g. Internal Scan / External Scan) by title
  3. Produce every output configured for that scan type:
       scan_results - the scan's own results (same as clicking the scan > Download)
       report       - a report from a Manual (scan-based) template
  4. Save everything to <output_dir>/<client>/<YYYY-MM>/ with readable names, e.g.
       <Client> - Internal Scan - 10-2026.csv
       <Client> - Internal Scan - Scan Report by Vulnerability - 10-2026.pdf
  5. Record the scan as processed (state file) so it is never reported twice

Run it on demand: pick clients from a numbered list, choose how many days back to
look (Enter keeps the config default), review the scans and outputs it found,
approve (or skip some), and it does the rest. Credentials come from the env vars
named in the config, then Windows Credential Manager (see --save-credentials), and
are prompted for if neither has them.

Usage:
  python qualys_report_fetch.py -c clients.yaml                       # menu -> preview -> approve
  python qualys_report_fetch.py -c clients.yaml --client NAME         # skip the menu
  python qualys_report_fetch.py -c clients.yaml --days 14             # look back 14 days
  python qualys_report_fetch.py -c clients.yaml --preview             # show plan only
  python qualys_report_fetch.py -c clients.yaml --redo                # re-download already-reported scans

Setup helpers:
  python qualys_report_fetch.py -c clients.yaml --save-credentials  # store login in Credential Manager
  python qualys_report_fetch.py -c clients.yaml --list-templates  # test login, get template IDs
  python qualys_report_fetch.py -c clients.yaml --list-scans      # check scan -> client/type matching
"""
import argparse
import getpass
import json
import logging
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

log = logging.getLogger("qualys-reports")

# v3 endpoints: the v2 report API reached end of life June 2026 and the v2 scan list
# reaches it December 2026 (Qualys VM/PC API User Guide). Same parameters and XML.
SCAN_PATH = "/api/3.0/fo/scan/"
REPORT_PATH = "/api/3.0/fo/report/"
# Scan results fetch is only documented on v2; try v3 first, then fall back.
SCAN_FETCH_PATHS = ("/api/3.0/fo/scan/", "/api/2.0/fo/scan/")

EXTENSIONS = {"pdf": "pdf", "csv": "csv", "csv_extended": "csv", "json": "json",
              "json_extended": "json", "xml": "xml", "html": "zip", "mht": "mht", "docx": "docx"}


class QualysError(Exception):
    pass


class QuotaExhausted(Exception):
    """Qualys API quota used up for longer than is worth waiting. Stops the whole run."""
    pass


MAX_THROTTLE_WAIT = 600   # seconds; longer waits mean the quota is used up -> stop the run

# Network drops worth one retry (e.g. "connection forcibly closed by the remote host")
RETRYABLE_NET_ERRORS = (requests.ConnectionError, requests.exceptions.ChunkedEncodingError,
                        requests.Timeout)


# Per-API rate-limit buckets as last reported by Qualys:
#   {api name: {"limit": n, "window": sec, "remaining": n, "seen": epoch}}
# Saved in the state file so the preview can show what's left before any calls are made.
API_USAGE = {}
CALLS_THIS_RUN = {}       # api name -> calls made this run
_PERSIST = None           # set by main(): saves the state file (incl. API_USAGE)


def _api_name(path, action):
    """Human name for a Qualys API endpoint; limits are counted per API."""
    kind = "scan" if "/scan/" in path else "report" if "/report/" in path else "api"
    return {("scan", "list"): "scan list", ("scan", "fetch"): "scan download",
            ("report", "launch"): "report launch", ("report", "list"): "report status",
            ("report", "fetch"): "report download", ("report", "delete"): "report delete",
            }.get((kind, action), f"{kind} {action}")


def _fmt_window(win):
    return "day" if win >= 86400 else f"{win // 3600} h" if win >= 3600 else f"{win // 60} min"


def _fmt_wait(sec):
    h, m = divmod(int(sec) // 60, 60)
    resets = datetime.now() + timedelta(seconds=sec)
    return f"{h}h {m}m (around {resets:%I:%M %p})" if h else f"{m}m (around {resets:%I:%M %p})"


class QualysClient:
    """Thin wrapper around the Qualys VM API with basic throttling handling."""

    def __init__(self, api_url, username, password, timeout=180):
        self.base = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers["X-Requested-With"] = "qualys-report-fetch"
        self.timeout = timeout
        self.calls = 0            # API calls made this run
        self.limit = None         # (limit, window_sec) from Qualys headers, once seen
        self.remaining = None     # calls left in the window, per the latest response
        self.fetch_path = None    # scan fetch endpoint that worked (saves a failed call per scan)
        self.low_warned = set()   # APIs we've already warned are nearly out of calls

    def _call(self, path, params, stream=False, max_retries=8):
        url = f"{self.base}{path}"
        for attempt in range(1, max_retries + 1):
            resp = self.session.post(url, data=params, timeout=self.timeout, stream=stream)
            self.calls += 1
            api = _api_name(path, params.get("action"))
            CALLS_THIS_RUN[api] = CALLS_THIS_RUN.get(api, 0) + 1
            lim = _int(resp.headers.get("X-RateLimit-Limit"))
            win = _int(resp.headers.get("X-RateLimit-Window-Sec"))
            rem = _int(resp.headers.get("X-RateLimit-Remaining"))
            if lim and win:
                self.limit = (lim, win)
            if rem is not None:
                self.remaining = rem
            if lim and win and rem is not None:
                API_USAGE[api] = {"limit": lim, "window": win, "remaining": rem, "seen": time.time()}

            # 409 = rate or concurrency limit; 429/503 = generic throttling
            if resp.status_code in (409, 429, 503):
                wait = _int(resp.headers.get("X-RateLimit-ToWait-Sec")) or min(60 * attempt, 300)
                if wait > MAX_THROTTLE_WAIT:
                    lim_txt = (f"{lim} calls per {_fmt_window(win)}" if lim and win else
                               f"{self.limit[0]} calls per {_fmt_window(self.limit[1])}" if self.limit else "its limit")
                    raise QuotaExhausted(
                        f"The Qualys '{api}' API is out of calls ({lim_txt}). It frees up in about "
                        f"{_fmt_wait(wait)}. Completed scans are saved; run again after that and the "
                        "rest will be picked up.")
                log.warning("Throttled (HTTP %s) on '%s'; waiting %ss (attempt %d/%d)",
                            resp.status_code, _api_name(path, params.get("action")), wait, attempt, max_retries)
                resp.close()
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                raise QualysError(f"HTTP {resp.status_code} on {params.get('action')}: {resp.text[:500]}")

            # Nearly out of calls on this API: warn, but DON'T pause. The window is a
            # rolling day, so a short wait frees nothing, and pausing here would leave a
            # streamed download idle until Qualys drops the connection. If the limit is
            # actually hit, the 409 handling above stops the run cleanly.
            remaining = _int(resp.headers.get("X-RateLimit-Remaining"))
            api = _api_name(path, params.get("action"))
            if remaining is not None and remaining <= 2 and api not in self.low_warned:
                self.low_warned.add(api)
                log.warning("Qualys '%s' API has %s call(s) left in its limit window; the run "
                            "may stop early and pick up the rest next time", api, remaining)
            return resp

        raise QualysError(f"Gave up on {params.get('action')} after {max_retries} throttled attempts")

    def _xml(self, path, params):
        resp = self._call(path, params)
        try:
            return ET.fromstring(resp.content)
        except ET.ParseError as e:
            raise QualysError(f"Unparseable response for {params.get('action')}: {e}") from e

    @staticmethod
    def _save_stream(resp, dest):
        tmp = dest.with_name(dest.name + ".part")
        try:
            with open(tmp, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    f.write(chunk)
            tmp.replace(dest)
        except BaseException:
            tmp.unlink(missing_ok=True)   # no half-written files left behind
            raise
        finally:
            resp.close()

    # --- scans -------------------------------------------------------------

    def list_finished_scans(self, since, client_name=None):
        params = {
            "action": "list",
            "state": "Finished",
            "launched_after_datetime": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "show_ags": "1",
        }
        if client_name:
            params["client_name"] = client_name  # Consultant subscriptions: server-side filter
        root = self._xml(SCAN_PATH, params)
        scans = []
        for s in root.iter("SCAN"):
            scans.append({
                "ref": s.findtext("REF"),
                "title": (s.findtext("TITLE") or "").strip(),
                "launched": s.findtext("LAUNCH_DATETIME"),
                "target": s.findtext("TARGET"),
                "state": s.findtext("STATUS/STATE"),
                "asset_groups": [(a.text or "").strip() for a in s.iter("ASSET_GROUP_TITLE")],
                "qualys_client": client_name,
            })
        return [s for s in scans if s["ref"]]

    def fetch_scan_results(self, scan_ref, output_format, mode, dest):
        """The scan's own results, as from the scan list's Download (csv/json only)."""
        params = {"action": "fetch", "scan_ref": scan_ref, "output_format": output_format}
        if mode:
            params["mode"] = mode
        errors = []
        paths = ([self.fetch_path] if self.fetch_path else []) + [x for x in SCAN_FETCH_PATHS if x != self.fetch_path]
        for path in paths:
            try:
                resp = self._call(path, params, stream=True)
            except QualysError as e:
                errors.append(f"{path}: {e}")
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "xml" in ctype and not output_format.startswith("xml"):
                # An XML body when CSV/JSON was asked for is an error message
                errors.append(f"{path}: {resp.content[:300]!r}")
                continue
            self.fetch_path = path
            try:
                self._save_stream(resp, dest)
            except RETRYABLE_NET_ERRORS as e:
                log.warning("Download of %s dropped (%s); retrying once", dest.name, type(e).__name__)
                self._download(path, params, dest, attempts=1)
            return
        raise QualysError("scan results fetch failed: " + " | ".join(errors))

    # --- reports -----------------------------------------------------------

    def launch_report(self, template_id, scan_ref, output_format, title):
        root = self._xml(REPORT_PATH, {
            "action": "launch",
            "template_id": str(template_id),
            "report_title": title[:128],
            "output_format": output_format,
            "report_refs": scan_ref,
        })
        for item in root.iter("ITEM"):
            if item.findtext("KEY") == "ID":
                return item.findtext("VALUE")
        raise QualysError(f"No report ID in launch response: {ET.tostring(root, encoding='unicode')[:500]}")

    def report_states(self, report_ids):
        """Status of several reports in ONE API call: {report_id: state}."""
        if len(report_ids) == 1:
            params = {"action": "list", "id": str(next(iter(report_ids)))}
        else:
            params = {"action": "list"}
        root = self._xml(REPORT_PATH, params)
        wanted = {str(r) for r in report_ids}
        states = {}
        for rpt in root.iter("REPORT"):
            rid = (rpt.findtext("ID") or "").strip()
            if rid in wanted or len(wanted) == 1:
                states[rid or next(iter(wanted))] = rpt.findtext("STATUS/STATE")
        return states

    def fetch_report(self, report_id, dest):
        self._download(REPORT_PATH, {"action": "fetch", "id": str(report_id)}, dest, attempts=2)

    def _download(self, path, params, dest, attempts=2):
        """Stream a file to dest, retrying a dropped connection. Each attempt is one API call."""
        for n in range(1, attempts + 1):
            try:
                resp = self._call(path, params, stream=True)
                self._save_stream(resp, dest)
                return
            except RETRYABLE_NET_ERRORS as e:
                if n == attempts:
                    raise
                log.warning("Download of %s dropped (%s); retrying in 15s", dest.name, type(e).__name__)
                time.sleep(15)

    def list_templates(self):
        resp = self.session.get(f"{self.base}/msp/report_template_list.php", timeout=self.timeout)
        if resp.status_code != 200:
            raise QualysError(f"HTTP {resp.status_code} listing templates: {resp.text[:500]}")
        root = ET.fromstring(resp.content)
        # Per the API guide: TYPE is Auto/Manual, TEMPLATE_TYPE is Scan/Policy/Patch/...
        return [{
            "id": t.findtext("ID"),
            "type": t.findtext("TYPE"),
            "template_type": t.findtext("TEMPLATE_TYPE"),
            "title": (t.findtext("TITLE") or "").strip(),
            "owner": t.findtext("USER/LOGIN") or "",
        } for t in root.iter("REPORT_TEMPLATE")]

    def delete_report(self, report_id):
        # Only documented on the v2 path; treat failure as a warning, not a failed run.
        try:
            self._xml(REPORT_PATH, {"action": "delete", "id": str(report_id)})
        except (QualysError, requests.RequestException) as e:
            log.warning("Could not delete report %s from Report Share: %s", report_id, e)


# --- helpers ---------------------------------------------------------------

def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def safe_folder(s, maxlen=80):
    s = re.sub(r"\s*-\s*", "-", s)
    s = re.sub(r"[^\w.-]+", "_", s).strip("_-")
    return s[:maxlen] or "client"


def safe_filename(s):
    """Keep spaces and readability; drop only characters Windows/macOS reject."""
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", s).strip(" .")
    return s[:150] or "report"


def _read_state_file(path):
    """Parsed state dict, or None if the file is missing, empty, or not valid state JSON."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None
    if not text.strip():
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("processed", {})
    return data


def load_state(path):
    """Load the record of already-reported scans, recovering from an empty or damaged file."""
    if not path.exists():
        return {"processed": {}}
    data = _read_state_file(path)
    if data is not None:
        return data

    backup = path.with_name(path.name + ".bak")
    empty = path.stat().st_size == 0 or not path.read_text(encoding="utf-8", errors="replace").strip()
    bak = _read_state_file(backup)
    if bak is not None:
        log.warning("%s is %s; using the backup copy from %s.", path.name,
                    "empty" if empty else "damaged",
                    datetime.fromtimestamp(backup.stat().st_mtime).strftime("%Y-%m-%d %I:%M %p"))
        return bak
    if empty:
        log.warning("%s is empty, so the script doesn't know which scans were already "
                    "reported. Starting fresh: every finished scan in the look-back window "
                    "will be offered again (you can skip ones you've done in the preview).", path.name)
        return {"processed": {}}
    # Non-empty but unreadable, and no backup: don't silently discard the history.
    keep = path.with_name(f"{path.stem}.damaged-{datetime.now():%Y%m%d-%H%M%S}{path.suffix}")
    path.replace(keep)
    log.warning("%s was damaged and has been moved to %s. Starting fresh: every finished "
                "scan in the look-back window will be offered again.", path.name, keep.name)
    return {"processed": {}}


def save_state(path, state):
    """Write atomically, keeping the previous good copy as <name>.bak."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    if _read_state_file(path) is not None:
        backup = path.with_name(path.name + ".bak")
        backup.write_bytes(path.read_bytes())
    tmp.replace(path)


_cred_cache = {}


KEYRING_SERVICE = "qualys-report-fetch"


def _keyring():
    """The keyring module (Windows Credential Manager backend on Windows), or None."""
    try:
        import keyring
        return keyring
    except ImportError:
        return None


def get_secret(env_name, label, hidden):
    """Env var, then Windows Credential Manager, then an interactive prompt.
    Cached so shared creds are asked for once per run."""
    if env_name in _cred_cache:
        return _cred_cache[env_name]
    val = os.environ.get(env_name)
    if not val:
        kr = _keyring()
        if kr:
            try:
                val = kr.get_password(KEYRING_SERVICE, env_name)
            except Exception as e:  # locked/unavailable backend: fall through to prompt
                log.debug("Credential store lookup failed for %s: %s", env_name, e)
    if not val and sys.stdin.isatty():
        val = getpass.getpass(f"{label}: ") if hidden else input(f"{label}: ").strip()
    _cred_cache[env_name] = val
    return val


def save_credentials(merged):
    """Prompt for Qualys credentials, verify they work, store them in Credential Manager."""
    kr = _keyring()
    if kr is None:
        sys.exit("The keyring package is needed for this: pip install keyring")
    pairs = sorted({(c["api_url"], c["username_env"], c["password_env"]) for c in merged})
    for api_url, user_env, pass_env in pairs:
        print(f"\nQualys login for {api_url}  (stored as {user_env} / {pass_env})")
        user = input("Username: ").strip()
        pw = getpass.getpass("Password: ")
        if not user or not pw:
            sys.exit("Username and password are both required. Nothing saved.")
        try:
            QualysClient(api_url, user, pw).list_templates()
        except (QualysError, requests.RequestException, ET.ParseError) as e:
            sys.exit(f"Login test failed, nothing saved: {e}")
        kr.set_password(KEYRING_SERVICE, user_env, user)
        kr.set_password(KEYRING_SERVICE, pass_env, pw)
        print("Login verified and saved to Windows Credential Manager.")
        if os.environ.get(user_env) or os.environ.get(pass_env):
            print(f"Note: {user_env}/{pass_env} environment variables are also set and take "
                  "priority. Remove them if they're out of date.")


def forget_credentials(merged):
    kr = _keyring()
    if kr is None:
        sys.exit("The keyring package is needed for this: pip install keyring")
    names = sorted({n for c in merged for n in (c["username_env"], c["password_env"])})
    for n in names:
        try:
            kr.delete_password(KEYRING_SERVICE, n)
            print(f"Removed {n}")
        except Exception:
            print(f"{n} was not stored")


def wait_for_reports(qc, pending, poll_sec, timeout_min):
    """pending: {report_id: anything}. Returns {report_id: final_state}."""
    deadline = time.monotonic() + timeout_min * 60
    states = {}
    first = True
    while pending and time.monotonic() < deadline:
        # Reports rarely finish in under a few minutes, so the first check waits
        # twice as long. Each check costs one call against the report list API limit.
        time.sleep(poll_sec * 2 if first else poll_sec)
        first = False
        current = qc.report_states(list(pending))   # one API call for all pending reports
        for rid in list(pending):
            st = current.get(str(rid))
            log.debug("Report %s state: %s", rid, st)
            if st in ("Finished", "Errors", "Canceled"):
                states[rid] = st
                pending.pop(rid)
    for rid in pending:
        states[rid] = "Timeout"
    return states


# --- config ----------------------------------------------------------------

def validate_scan_types(cfg):
    """Return a list of problems with a client's scan_types config (empty = OK)."""
    problems = []
    types = cfg.get("scan_types") or {}
    if not types:
        problems.append("no scan_types defined")
    for tname, t in types.items():
        if not (t or {}).get("match"):
            problems.append(f"scan type '{tname}' has no match pattern")
        for o in (t or {}).get("outputs") or []:
            kind = o.get("kind")
            if kind not in ("scan_results", "report"):
                problems.append(f"'{tname}': output kind must be scan_results or report, got {kind!r}")
            elif kind == "scan_results" and o.get("format") not in ("csv", "json", "csv_extended", "json_extended"):
                problems.append(f"'{tname}': scan_results format must be csv or json (PDF needs a report template)")
            elif kind == "report" and not o.get("format"):
                problems.append(f"'{tname}': report output needs a format")
    return problems


def output_label(o):
    base = o.get("name") or "Scan results"
    return f"{base} ({o['format'].upper()})"


def output_ready(o):
    return o["kind"] == "scan_results" or bool(o.get("template"))


# --- planning and execution ------------------------------------------------

def scan_matches(cfg, scan):
    """True if a scan belongs to this client and isn't excluded. Every filter that is set must pass."""
    qclient = cfg.get("qualys_client")
    if qclient and (scan.get("qualys_client") or "").lower() != qclient.lower():
        return False
    exclude = cfg.get("exclude_title_match")
    if exclude and re.search(exclude, scan["title"], re.IGNORECASE):
        return False
    groups = cfg.get("asset_groups")
    if groups:
        wanted = {g.strip().lower() for g in groups}
        if not wanted & {g.lower() for g in scan["asset_groups"]}:
            return False
    pattern = cfg.get("scan_title_match")
    if pattern and not re.search(pattern, scan["title"]):
        return False
    return True


def scan_type_for(cfg, scan):
    """Name of the first scan type whose `match` regex fits the title and whose optional
    `exclude` regex doesn't (both case-insensitive), else None."""
    for tname, t in (cfg.get("scan_types") or {}).items():
        if t.get("exclude") and re.search(t["exclude"], scan["title"], re.IGNORECASE):
            continue
        if re.search(t["match"], scan["title"], re.IGNORECASE):
            return tname
    return None


def lookback_for(cfg, settings):
    """Days to look back: run override (--days / menu) > client's lookback_days > global."""
    return settings.get("days_override") or cfg.get("lookback_days") or settings["lookback_days"]


def plan_client(client, defaults, settings, state, cache):
    """Find this client's finished scans not yet reported. Returns (qc, cfg, scans, untyped).

    `cache` reuses one login per credential set and one scan list per Qualys client.
    Each returned scan carries its 'scan_type'. `untyped` are scans that matched the
    client but no scan type (e.g. Host Discovery); they are not reported.
    """
    name = client["name"]
    cfg = {**defaults, **client}
    login_key = (cfg["api_url"], cfg["username_env"])
    days = lookback_for(cfg, settings)
    list_key = (*login_key, cfg.get("qualys_client"), days)

    if login_key not in cache:
        user = get_secret(cfg["username_env"], "Qualys username", hidden=False)
        pw = get_secret(cfg["password_env"], "Qualys password", hidden=True)
        if not user or not pw:
            raise QualysError(f"missing credentials ({cfg['username_env']} / {cfg['password_env']})")
        cache[login_key] = QualysClient(cfg["api_url"], user, pw)
    qc = cache[login_key]

    if list_key not in cache:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        cache[list_key] = qc.list_finished_scans(since, cfg.get("qualys_client"))
    done = set(state["processed"].get(name, []))
    redo = settings.get("redo")

    typed, untyped = [], []
    for s in cache[list_key]:
        if (s["ref"] in done and not redo) or not scan_matches(cfg, s):
            continue
        t = scan_type_for(cfg, s)
        if t:
            typed.append({**s, "scan_type": t, "redo": s["ref"] in done})
        else:
            untyped.append(s)
    return qc, cfg, typed, untyped


def run_plan(plan, settings, state, state_path):
    """Produce every output for every scan in the plan, sharing report status checks.

    1. Download all scan-results CSVs (immediate) and queue all template reports.
    2. Keep up to `max_concurrent_reports` reports running in Qualys; ONE status
       call per cycle covers every running report in the whole run.
    3. Download each report as it finishes and launch the next queued one.
    4. Record a scan as processed the moment all of its outputs are saved.

    Returns ({client: [saved paths]}, [client names with failures]).
    """
    used = {}             # (client, YYYY-MM) -> file names already taken this run
    saved_by_client = {}
    failed = set()
    left = {}             # plan index -> outputs still outstanding
    ok = {}               # plan index -> no failures so far
    queue = []            # (plan index, output, destination) waiting to launch

    def dest_for(i, o):
        p = plan[i]
        parts = [p["label"], p["scan"]["scan_type"]] + ([o["name"]] if o.get("name") else []) + [p["month_tag"]]
        base = safe_filename(" - ".join(parts))
        ext = EXTENSIONS.get(o["format"], o["format"])
        names = used.setdefault((p["cfg"]["name"], p["launched"][:7]), set())
        fname = f"{base}.{ext}"
        if fname in names:  # two scans of the same type this month: add the date
            fname = f"{base} ({p['launched'][:10]}).{ext}"
        names.add(fname)
        return p["month_dir"] / fname

    def mark_processed(i):
        p = plan[i]
        done = state["processed"].setdefault(p["cfg"]["name"], [])
        if p["scan"]["ref"] not in done:
            done.append(p["scan"]["ref"])
        save_state(state_path, state)

    def finish_output(i, success, path=None):
        name = plan[i]["cfg"]["name"]
        if success:
            saved_by_client.setdefault(name, []).append(str(path))
            log.info("[%s]   saved %s", name, path.name)
        else:
            ok[i] = False
            failed.add(name)
        left[i] -= 1
        if left[i] == 0 and ok[i]:
            mark_processed(i)

    # Phase 1: immediate scan-results downloads; queue every template report
    for i, p in enumerate(plan):
        cfg, scan = p["cfg"], p["scan"]
        p["launched"] = scan["launched"] or datetime.now(timezone.utc).isoformat()
        p["label"] = cfg.get("label") or cfg["name"]
        p["month_tag"] = f"{p['launched'][5:7]}-{p['launched'][:4]}"
        p["month_dir"] = Path(settings["output_dir"]) / safe_folder(cfg["name"]) / p["launched"][:7]
        p["month_dir"].mkdir(parents=True, exist_ok=True)
        log.info("[%s] %s: %s (%s)", cfg["name"], scan["scan_type"], scan["title"], p["launched"][:10])

        outs = cfg["scan_types"][scan["scan_type"]].get("outputs") or []
        for o in outs:
            if not output_ready(o):
                log.warning("[%s]   skipping %s: no template ID set in config", cfg["name"], output_label(o))
        outs = [o for o in outs if output_ready(o)]
        left[i], ok[i] = len(outs), True
        if not outs:
            mark_processed(i)
            continue
        for o in outs:
            dest = dest_for(i, o)        # reserve names in plan order
            if o["kind"] == "scan_results":
                try:
                    p["qc"].fetch_scan_results(scan["ref"], o["format"], o.get("mode", "extended"), dest)
                    finish_output(i, True, dest)
                except (QualysError, requests.RequestException) as e:
                    log.error("[%s]   %s failed: %s", cfg["name"], output_label(o), e)
                    finish_output(i, False)
            else:
                queue.append((i, o, dest))

    # Phase 2: run the report queue with shared status checks
    max_inflight = max(1, settings["max_concurrent_reports"])
    poll = settings["poll_interval_sec"]
    timeout = settings["report_timeout_min"] * 60
    inflight = {}         # report id -> (plan index, output, destination, launched at)
    first_wait = True
    if queue:
        log.info("Queued %d template report(s); up to %d run at a time in Qualys", len(queue), max_inflight)
    while queue or inflight:
        while queue and len(inflight) < max_inflight:
            i, o, dest = queue.pop(0)
            p = plan[i]
            title = (f"{p['label']} - {p['scan']['scan_type']}" + (f" - {o['name']}" if o.get("name") else "")
                     + f" - {p['month_tag']}")
            try:
                rid = str(p["qc"].launch_report(o["template"], p["scan"]["ref"], o["format"], title))
            except (QualysError, requests.RequestException) as e:
                log.error("[%s]   %s launch failed: %s", p["cfg"]["name"], output_label(o), e)
                finish_output(i, False)
                continue
            log.info("[%s]   launched %s (report %s)", p["cfg"]["name"], output_label(o), rid)
            inflight[rid] = (i, o, dest, time.monotonic())
        if not inflight:
            continue

        time.sleep(poll * 2 if first_wait else poll)   # reports rarely finish in < a few minutes
        first_wait = False

        by_login = {}
        for rid, (i, *_rest) in inflight.items():
            qc = plan[i]["qc"]
            by_login.setdefault(id(qc), (qc, []))[1].append(rid)
        for qc, rids in by_login.values():
            states = qc.report_states(rids)                # ONE call for all running reports
            for rid in rids:
                i, o, dest, t0 = inflight[rid]
                name = plan[i]["cfg"]["name"]
                st = states.get(rid)
                log.debug("Report %s state: %s", rid, st)
                if st == "Finished":
                    del inflight[rid]
                    try:
                        qc.fetch_report(rid, dest)
                        finish_output(i, True, dest)
                        if settings.get("delete_after_fetch"):
                            qc.delete_report(rid)
                    except (QualysError, requests.RequestException) as e:
                        log.error("[%s]   download of report %s failed: %s", name, rid, e)
                        finish_output(i, False)
                elif st in ("Errors", "Canceled") or time.monotonic() - t0 > timeout:
                    del inflight[rid]
                    log.error("[%s]   %s (report %s) ended in state %s", name, output_label(o), rid, st or "Timeout")
                    finish_output(i, False)

    return saved_by_client, sorted(failed)


# --- interactive prompts ---------------------------------------------------

def parse_selection(text, n):
    """'all', '1,3', '2-4', '1 3 5' -> sorted 0-based indices, or None if invalid."""
    text = text.strip().lower()
    if text in ("all", "a", "*"):
        return list(range(n))
    picked = set()
    for part in re.split(r"[,\s]+", text):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            return None
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if lo < 1 or hi > n or lo > hi:
            return None
        picked.update(range(lo - 1, hi))
    return sorted(picked) or None


def choose_clients(clients):
    print("\nClients in config:")
    for i, c in enumerate(clients, 1):
        qclient = c.get("qualys_client")
        extra = f"  ({qclient})" if qclient and qclient != c["name"] else ""
        print(f"  {i:>3}. {c['name']}{extra}")
    while True:
        text = input("\nSelect clients (e.g. 1,3,5 or 2-4 or all; Enter to quit): ").strip()
        if not text:
            return []
        idx = parse_selection(text, len(clients))
        if idx is not None:
            return [clients[i] for i in idx]
        print("  Didn't understand that; use numbers from the list, ranges like 2-4, or 'all'.")


def ask_days(default_txt):
    """Prompt for a look-back window. Enter keeps the configured default (returns None)."""
    while True:
        text = input(f"\nLook back how many days for finished scans? (Enter = {default_txt}): ").strip()
        if not text:
            return None
        if text.isdigit() and 1 <= int(text) <= 365:
            return int(text)
        print("  Enter a whole number of days from 1 to 365, or press Enter for the default.")


def print_plan(plan):
    ready_total = skipped_total = 0
    for i, p in enumerate(plan, 1):
        s = p["scan"]
        again = "  |  ALREADY REPORTED (re-download)" if s.get("redo") else ""
        print(f"\n  {i:>3}. {p['cfg']['name']}  |  {s['scan_type']}  |  {(s['launched'] or '')[:10]}{again}")
        print(f"       {s['title']}")
        for o in p["cfg"]["scan_types"][s["scan_type"]].get("outputs") or []:
            if output_ready(o):
                ready_total += 1
                print(f"         - {output_label(o)}")
            else:
                skipped_total += 1
                print(f"         - {output_label(o)}   <-- SKIPPED: no template ID in config")
    msg = f"\n  {len(plan)} scan(s), {ready_total} output(s) to generate"
    if skipped_total:
        msg += f", {skipped_total} skipped (not configured)"
    print(msg)


def estimate_calls(plan, settings):
    """Rough API-call cost of running the plan, per Qualys API (limits are counted per API)."""
    est = {"report launch": 0, "report download": 0, "report status": 0, "scan download": 0}
    if settings.get("delete_after_fetch"):
        est["report delete"] = 0
    for p in plan:
        outs = [o for o in p["cfg"]["scan_types"][p["scan"]["scan_type"]].get("outputs") or [] if output_ready(o)]
        n_rep = sum(o["kind"] == "report" for o in outs)
        est["scan download"] += sum(o["kind"] == "scan_results" for o in outs)
        est["report launch"] += n_rep
        est["report download"] += n_rep
        if "report delete" in est:
            est["report delete"] += n_rep
    # Status checks are shared across the whole run: ~one round of checks per
    # "wave" of up to max_concurrent_reports reports (each wave ~6-8 minutes).
    n_reports = est["report launch"]
    if n_reports:
        poll = settings["poll_interval_sec"]
        per_wave = max(1, -(-(8 * 60 - 2 * poll) // poll) + 1)
        waves = -(-n_reports // max(1, settings["max_concurrent_reports"]))
        est["report status"] = waves * per_wave
    return {k: v for k, v in est.items() if v}


def _bucket_left(api):
    """(remaining, limit, note) for an API from the last time Qualys reported it."""
    b = API_USAGE.get(api)
    if not b:
        return None, None, "not checked yet"
    age = time.time() - b["seen"]
    if age >= b["window"]:
        return b["limit"], b["limit"], "window has fully reset"
    when = datetime.fromtimestamp(b["seen"]).strftime("%I:%M %p").lstrip("0")
    day = "" if age < 12 * 3600 else datetime.fromtimestamp(b["seen"]).strftime(" %a")
    return b["remaining"], b["limit"], f"as of{day} {when}"


def print_api_table(title, rows):
    """rows: [(api, needed_or_used, remaining, limit, note)]"""
    print(f"\n  {title}")
    print(f"    {'API':<17} {'this run':>9}   {'left / limit':<14} ")
    for api, n, rem, lim, note in rows:
        left = f"{rem} / {lim}" if lim is not None else "?"
        print(f"    {api:<17} {n:>9}   {left:<14} {note}")


def print_budget(plan, settings):
    est = estimate_calls(plan, settings)
    rows, short = [], []
    for api in ("scan list", "scan download", "report launch", "report status", "report download", "report delete"):
        if api not in est and api != "scan list":
            continue
        need = est.get(api, 0) if api != "scan list" else CALLS_THIS_RUN.get("scan list", 0)
        rem, lim, note = _bucket_left(api)
        label = f"~{need}" if api != "scan list" else f"{need} (done)"
        rows.append((api, label, rem, lim, note))
        if rem is not None and api != "scan list" and need > rem:
            short.append(f"{api} needs ~{need} but had {rem} left")
    print_api_table("Qualys API calls -- each API has its own limit, shared by everyone on the subscription:", rows)
    if short:
        print("\n  WARNING: " + "; ".join(short) + ".")
        print("  Calls free up over time (rolling window), but the run may stop partway.")
        print("  Consider skipping some scans and running them later.")


def approve_plan(plan, settings):
    while plan:
        print_plan(plan)
        print_budget(plan, settings)
        text = input("\nGenerate these? [y] yes / [n] cancel / or scan numbers to SKIP (e.g. 2,4): ").strip().lower()
        if text in ("y", "yes"):
            return plan
        if text in ("", "n", "no"):
            return []
        idx = parse_selection(text, len(plan))
        if idx is None:
            print("  Didn't understand that.")
            continue
        plan = [p for i, p in enumerate(plan) if i not in idx]
    print("\nNothing left to run.")
    return []


# --- main ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", required=True, help="Path to clients YAML config")
    ap.add_argument("--client", nargs="+", metavar="NAME", help="Skip the menu and use these client name(s)")
    ap.add_argument("--days", type=int, metavar="N",
                    help="Look back N days for finished scans (overrides the config; skips the menu prompt)")
    ap.add_argument("--redo", action="store_true",
                    help="Also offer scans that were already reported, to re-download them "
                         "(skip any you don't want in the preview)")
    ap.add_argument("--preview", action="store_true", help="Show what would be generated, then exit")
    ap.add_argument("--yes", action="store_true", help="Skip the approval prompt")
    ap.add_argument("--list-templates", action="store_true",
                    help="Test API access and list report template IDs")
    ap.add_argument("--list-scans", action="store_true",
                    help="Setup aid: list recent finished scans per client and how each would be handled")
    ap.add_argument("--save-credentials", action="store_true",
                    help="Prompt for your Qualys login, test it, and store it in Windows Credential Manager")
    ap.add_argument("--forget-credentials", action="store_true",
                    help="Remove the stored Qualys login from Windows Credential Manager")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Show extra detail, such as each report status check (useful when troubleshooting)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    interactive = sys.stdin.isatty()

    conf = yaml.safe_load(Path(args.config).read_text())
    settings = {
        "output_dir": conf.get("output_dir", "./reports"),
        "lookback_days": conf.get("lookback_days", 35),
        "poll_interval_sec": conf.get("poll_interval_sec", 120),
        "report_timeout_min": conf.get("report_timeout_min", 90),
        "max_concurrent_reports": conf.get("max_concurrent_reports", 10),
        "delete_after_fetch": conf.get("delete_after_fetch", False),
        "days_override": None,
        "redo": args.redo,
    }
    if args.days is not None:
        if not 1 <= args.days <= 365:
            sys.exit("--days must be between 1 and 365")
        settings["days_override"] = args.days
    state_path = Path(conf.get("state_file", "./qualys_report_state.json"))
    state = load_state(state_path)
    API_USAGE.update(state.get("api_buckets", {}))
    state["api_buckets"] = API_USAGE          # saved whenever the state file is saved
    global _PERSIST
    _PERSIST = lambda: save_state(state_path, state)
    defaults = conf.get("defaults", {})

    clients = conf["clients"]
    merged = [{**defaults, **c} for c in clients]

    # Config sanity: every client needs usable scan types
    problems = [f"{c['name']}: {p}" for c in merged for p in validate_scan_types(c)]
    if problems:
        sys.exit("Config problems:\n  " + "\n  ".join(problems))

    # Safety: clients sharing a Qualys login see each other's scans. Every one of
    # them needs a filter, or reports could go to the wrong client.
    shared = {}
    for c in merged:
        shared.setdefault((c["api_url"], c["username_env"]), []).append(c)
    unsafe = [c["name"] for grp in shared.values() if len(grp) > 1
              for c in grp if not (c.get("qualys_client") or c.get("asset_groups") or c.get("scan_title_match"))]
    if unsafe:
        sys.exit("These clients share a Qualys login but have no qualys_client (or asset_groups / "
                 f"scan_title_match), so they could pick up other clients' scans: {', '.join(unsafe)}")

    if args.save_credentials:
        save_credentials(merged)
        return
    if args.forget_credentials:
        forget_credentials(merged)
        return

    if args.list_templates:
        cfg = merged[0]
        user = get_secret(cfg["username_env"], "Qualys username", hidden=False)
        pw = get_secret(cfg["password_env"], "Qualys password", hidden=True)
        try:
            templates = QualysClient(cfg["api_url"], user, pw).list_templates()
        except (QualysError, requests.RequestException, ET.ParseError) as e:
            sys.exit(f"API check failed at {cfg['api_url']}: {e}")
        print(f"\nAPI access OK ({cfg['api_url']})")
        scan_t = [t for t in templates if (t["template_type"] or "").lower() == "scan"]
        manual = [t for t in scan_t if (t["type"] or "").lower() == "manual"]
        auto = [t for t in scan_t if (t["type"] or "").lower() != "manual"]
        print("\nManual (scan-based) scan templates -- usable as `template:` in scan_types:\n")
        for t in manual:
            owner = "  [Qualys system template]" if t["owner"].lower() == "system" else ""
            print(f"  {t['id']:>10}  {t['title']}{owner}")
        if not manual:
            print("  (none found)")
        if auto:
            print("\nAuto (host-based) scan templates -- NOT usable, they don't report on a specific scan:\n")
            for t in auto:
                print(f"  {t['id']:>10}  {t['title']}")
        other = len(templates) - len(scan_t)
        print(f"\n{other} non-scan template(s) not shown (policy, patch, remediation, etc.)")
        return

    if args.list_scans:
        # Setup aid: per configured client, show the finished scans Qualys returns and
        # what would happen to each. Ignores the state file.
        cache = {}
        print("\nFinished scans by client:")
        for c in merged:
            raw = {k: v for k, v in c.items() if k not in ("exclude_title_match", "asset_groups", "scan_title_match")}
            try:
                _, _, typed, untyped = plan_client(raw, {}, settings, {"processed": {}}, cache)
            except (QualysError, requests.RequestException) as e:
                print(f"\n[{c['name']}]  ERROR: {e}")
                continue
            label = f"Qualys client '{c['qualys_client']}'" if c.get("qualys_client") else "all scans (no qualys_client set)"
            print(f"\n[{c['name']}]  {label}, last {lookback_for(c, settings)} days")
            rows =[(s, s["scan_type"]) for s in typed] + [(s, None) for s in untyped]
            if not rows:
                print("    (no finished scans -- check qualys_client matches the Qualys Client name exactly)")
            for s, t in sorted(rows, key=lambda r: r[0]["launched"] or ""):
                if t and scan_matches(c, s):
                    mark = f"{t:<16}"
                elif t:
                    mark = f"{'excluded':<16}"
                else:
                    mark = f"{'not reported':<16}"
                print(f"    {mark}  {(s['launched'] or '')[:10]}  {s['title']}")
        print()
        return

    # 1. Pick clients
    if args.client:
        by_name = {c["name"]: c for c in clients}
        missing = [n for n in args.client if n not in by_name]
        if missing:
            sys.exit(f"Not in config: {', '.join(missing)}")
        selected = [by_name[n] for n in args.client]
    elif interactive:
        selected = choose_clients(clients)
        if not selected:
            sys.exit("No clients selected.")
    else:
        sys.exit("Not running in a terminal: pass --client NAME [NAME ...]")

    # 1b. How far back to look (menu prompt unless --days was given)
    if not settings.get("days_override") and interactive and not args.client:
        defaults_shown = sorted({lookback_for({**defaults, **c}, settings) for c in selected})
        default_txt = (f"{defaults_shown[0]} days" if len(defaults_shown) == 1 else
                       f"each client's own setting, {defaults_shown[0]}-{defaults_shown[-1]} days")
        settings["days_override"] = ask_days(default_txt)

    # 2. Find new finished scans for each selected client
    print()
    plan, failures, cache = [], [], {}
    for client in selected:
        log.info("[%s] checking for finished scans...", client["name"])
        try:
            qc, cfg, scans, untyped = plan_client(client, defaults, settings, state, cache)
        except (QualysError, requests.RequestException) as e:
            log.error("[%s] %s", client["name"], e)
            failures.append(client["name"])
            continue
        for s in untyped:
            log.info("[%s] not reporting '%s' (not an Internal/External scan per scan_types)", client["name"], s["title"])
        if not scans:
            log.info("[%s] no new finished scans in the last %d days", client["name"], lookback_for(cfg, settings))
        plan += [{"qc": qc, "cfg": cfg, "scan": s} for s in scans]

    # Safety: a scan that matches more than one configured client (selected or not)
    # is ambiguous. Leave it out rather than guess which client gets it.
    ambiguous = []
    for p in plan:
        key = (p["cfg"]["api_url"], p["cfg"]["username_env"])
        owners = [c["name"] for c in shared[key] if scan_matches(c, p["scan"])]
        if len(owners) > 1:
            ambiguous.append(p)
            log.error("Scan '%s' (%s) matches more than one client: %s. Skipped.",
                      p["scan"]["title"], p["scan"]["ref"], ", ".join(owners))
    plan = [p for p in plan if p not in ambiguous]
    for p in ambiguous:
        if p["cfg"]["name"] not in failures:
            failures.append(p["cfg"]["name"])

    if not plan:
        print("\nNothing to generate for the selected clients.")
        sys.exit(1 if failures else 0)

    plan.sort(key=lambda p: (p["cfg"]["name"], p["scan"]["scan_type"], p["scan"]["launched"] or ""))

    # 3. Preview and approve
    if args.preview:
        print_plan(plan)
        print_budget(plan, settings)
        return
    if not args.yes:
        if not interactive:
            sys.exit("Approval needed: run in a terminal, or pass --yes")
        plan = approve_plan(plan, settings)
        if not plan:
            sys.exit("Cancelled.")

    # 4. Generate and download
    print()
    saved_by_client, run_failures = run_plan(plan, settings, state, state_path)
    for name in run_failures:
        if name not in failures:
            failures.append(name)

    if any(saved_by_client.values()):
        print("\nFiles saved:")
        for name, files in saved_by_client.items():
            if files:
                print(f"\n  {name}  ({Path(files[0]).parent})")
                for f in files:
                    print(f"    {Path(f).name}")

    if CALLS_THIS_RUN:
        rows = []
        for api, n in CALLS_THIS_RUN.items():
            rem, lim, note = _bucket_left(api)
            rows.append((api, str(n), rem, lim, "now" if note.startswith("as of") else note))
        print_api_table(f"Qualys API calls this run ({sum(CALLS_THIS_RUN.values())} total):", rows)

    if failures:
        log.error("Finished with problems for: %s (failed scans will show up again next run)", ", ".join(failures))
        sys.exit(1)
    print("\nDone.")


if __name__ == "__main__":
    try:
        try:
            main()
        finally:
            if _PERSIST:          # remember per-API usage even if the run stopped early
                try:
                    _PERSIST()
                except OSError:
                    pass
    except QuotaExhausted as e:
        print(f"\nSTOPPED: {e}")
        sys.exit(2)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        sys.exit(130)
