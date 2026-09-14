# fw-scout

A firmware hidden-region and backdoor scanner. It takes a firmware image (or an
already-extracted root filesystem), extracts it, and runs a pipeline of static
analysers that look for the things that actually turn up in consumer router
firmware: hardcoded keys and credentials, backdoor accounts, latent debug
interfaces, and unexplained high-entropy regions that may hide encrypted data.

`fw-scout` was built to **codify a manual firmware-analysis methodology** into a
repeatable tool. Its detection logic — especially the entropy classifier and the
key validator — encodes lessons learned the hard way during hands-on research,
where naive heuristics produced false positives that had to be walked back.

## Why it is not just a grep wrapper

Two design decisions carry most of the value:

1. **Entropy alone does not distinguish encrypted from compressed data.** Both
   sit near 8.0 bits/byte. `fw-scout` only flags a region as encryption-like when
   it is *near-maximal entropy* **and** *serially uncorrelated* **and** *fails
   decompression* **and** *is not an already-compressed media/asset type*. Any one
   of those signals alone is noise — a scanner that flags "entropy > 7.5" fires on
   every PNG, font, and squashfs in the image.

2. **A `BEGIN PRIVATE KEY` string is not a key finding.** A real firmware image
   was found to ship a structurally corrupted PEM whose bytes did not parse as a
   key. `fw-scout` attempts a structural parse (strip markers → base64 → DER → ASN.1
   sanity) and only raises a HIGH key finding when the material actually parses.
   Otherwise it reports the marker as *informational*, not a key exposure.

## Install

```bash
git clone https://github.com/YOURUSER/fw-scout
cd fw-scout
pip install -e .              # core (stdlib only)
pip install -e ".[yara]"      # add YARA scanning (optional)
pip install -e ".[dev]"       # tests + linters
```

Extraction uses `binwalk` (preferred) or `unblob` if present on `PATH`. Neither
is required to analyse an already-extracted directory.

## Usage

```bash
# scan a firmware image (extracts, then analyses)
fw-scout firmware.img -o report/

# scan an already-extracted root filesystem
fw-scout ./_firmware.img.extracted/squashfs-root -o report/

# module form
python -m fw_scout.cli firmware.img -o report/
```

Outputs `report/report.json` (machine-readable) and `report/report.md`
(human-readable). See [`examples/example-report.md`](examples/example-report.md)
for sample output produced against a synthetic test rootfs.

## What it checks

| Analyser | Looks for |
|---|---|
| `entropy`  | High-entropy regions, classified encrypted-like / compressed / unknown |
| `secrets`  | PEM private keys (structurally validated), SSH authorized_keys, AWS keys, credential assignments (placeholder-filtered) |
| `accounts` | Second UID-0 accounts, service accounts with shells, set/weak password hashes, empty-password fields, duplicate entries |
| `yara`     | Bundled firmware rules: telnet/debug-enable interfaces, format-string command exec, unauth info endpoints |

## Severity and confidence

Every finding carries a **severity** and a **confidence**. `fw-scout` is
deliberately conservative about confidence: an empty shadow password field is
`MEDIUM`/`low-confidence` because firmware frequently populates it at first boot,
so the image field is a lead, not a proven passwordless account. The reports say
so in the finding text. Static analysis observes; it does not prove
exploitability — confirm against a live device before asserting a vulnerability.

## Design

```
fw_scout/
├── findings.py        # shared Finding data model + secret redaction
├── entropy.py         # Shannon entropy + serial correlation + classifier
├── secrets.py         # key/credential detection with structural validation
├── accounts.py        # passwd/shadow backdoor-account analysis
├── extract.py         # binwalk/unblob wrapper + rootfs discovery
├── yara_runner.py     # optional YARA scanning (graceful no-op if absent)
├── scanner.py         # orchestrates the pipeline
├── cli.py             # command-line entry point
├── rules/             # bundled YARA rules
└── reporters/         # JSON + Markdown output
```

## Extending

- **Add a YARA rule:** drop a `.yar` file in `fw_scout/rules/`. Set a `severity`
  meta (`info`/`low`/`medium`/`high`/`critical`) and a `description`; it is picked
  up automatically.
- **Add an analyser:** write a module that returns `list[Finding]` and call it
  from `scanner.scan()`. Reporters need no changes.

## Tests

```bash
pytest -q
```

The suite locks in the two anti-false-positive behaviours above.

## Legal

Analyse only firmware you are authorised to examine (images you own, download
lawfully from a vendor, or that are published for testing). `fw-scout` is for
defensive research and coordinated disclosure. It does not exploit anything.

## License

MIT. See [LICENSE](LICENSE).
