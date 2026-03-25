# What this project is

This project is a small util that allow a user that has been infected by the litellm malware to discover which secrets have been compromised and remediate these using GitGuardian.

# How to use it
First, clone the repository on the infected machine.

## Requirements

- Python 3 with `pip`
- `curl`
- A GitGuardian API token with the `incidents:write` and `sources:write`
  scopes (Personal Access Token from your GitGuardian workspace settings)

## Usage

```sh
GITGUARDIAN_API_KEY=<token> sh scan.sh --source-name <name> [--output <file.zip>] --send
```

| Option | Required | Description |
|---|---|---|
| `--source-name NAME` | Yes | Name of the GitGuardian source to create |
| `--output PATH` | No | Output ZIP path (default: `harvested_credentials.zip`) |

## Examples

Basic run:
```sh
GITGUARDIAN_API_KEY=ggtt-xxxxxxxxxxxx sh scan.sh --source-name prod-server-01 --send
```

Custom output path:
```sh
GITGUARDIAN_API_KEY=ggtt-xxxxxxxxxxxx sh scan.sh --source-name prod-server-01 --output /tmp/scan.zip --send
```

Dry-run (will not send the secrets to GitGuardian)
```
GITGUARDIAN_API_KEY=ggtt-xxxxxxxxxxxx sh scan.sh --source-name prod-server-01 --output /tmp/scan.zip
```

Using stored ggshield credentials (interactive auth, no source creation):
```sh
sh scan.sh --source-name prod-server-01
# will prompt: ggshield auth login
# note: source creation requires GITGUARDIAN_API_KEY
```


## What it does

1. **Installs ggshield** if not already present (`pip install ggshield`).
2. **Authenticates** with GitGuardian — uses the `GITGUARDIAN_API_KEY`
   environment variable if set, otherwise checks for stored ggshield
   credentials and prompts `ggshield auth login` if needed.
3. **Verifies token permissions** — checks that the token has the
   `incidents:write` and `sources:write` scopes required to create incidents
   and sources in the dashboard. Exits with a clear error if any scope is
   missing.
4. **Creates a source** in the GitGuardian dashboard under the name you
   provide. This associates the scan results with a named, trackable source.
5. **Harvests files** by running `gather_files.py`, which collects credentials,
   SSH keys, cloud configs, and other sensitive files from the machine into a
   ZIP archive.
6. **Scans the archive** with `ggshield secret scan archive --create-incidents`,
   creating incidents in the GitGuardian dashboard for every secret found.

## Notes

- Source creation and permission checks require `GITGUARDIAN_API_KEY` to be
  set. Running without it falls back to interactive `ggshield auth login` for
  the scan only, but the script will exit if `--source-name` is provided
  without the key.
- The ZIP archive is not deleted after the scan. Remove it manually if needed.
- The script is POSIX sh compatible and runs on any Unix-like system.
