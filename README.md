# Qualys Report Fetch — Quick Guide

Generates and downloads monthly Qualys VA scan reports for selected clients.
For each Internal / External scan it saves the scan CSV plus the template PDFs
to `reports\<client>\<YYYY-MM>\`, named like
`<Client> - Internal Scan - 10-2026.pdf`.

## Requirements
- Python 3 (check "Add Python to PATH" when installing on Windows)
- `pip install requests pyyaml keyring`
- A Qualys login with **API Access** enabled on your role

## First-time setup
1. Save your Qualys login (tested, then stored in Windows Credential Manager):
   `python qualys_report_fetch.py -c clients.yaml --save-credentials`
2. Check which scans each client will pick up:
   `python qualys_report_fetch.py -c clients.yaml --list-scans`

## Running it
`python qualys_report_fetch.py -c clients.yaml`

Pick clients by number → choose days to look back (Enter = default) →
review the list → `y` to generate. Template reports take a few minutes each.

Useful options: `--client NAME` (skip menu), `--days N`, `--preview`, `--help`.

## Good to know
- Each scan is only reported once (tracked in `qualys_report_state.json`).
  To re-download reports, run with `--redo` and pick them in the preview
  (no need to edit the state file).
  Only run clients you own, so reports aren't duplicated across analysts.
- Scans are sorted by title: "Internal" / "External" are reported,
  "Host Discovery" is skipped. Adjust in `clients.yaml` under `scan_types`.
- Password changed? Run `--save-credentials` again.
- **API limit: 50 calls per day per API, shared by the whole subscription**
  (Qualys Consultant service level). Each client (Internal + External) uses
  ~5 report launches and ~5 report downloads; status checks are shared across
  the whole run (~4 per batch of 10 reports). So the team can run about
  **10 clients per day combined**, and selecting several clients in one run is
  cheaper than separate runs. The preview shows a table of each API's estimated calls and what's left (from the
  last time Qualys reported it). If the limit is
  hit, the script stops and says when it frees up; just rerun then. Qualys
  Support can raise the limits if needed.
- **Don't share the `reports` folder** — it contains client vulnerability data.
