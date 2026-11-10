# Custom YARA Rules Directory

Place any custom `.yar` or `.yara` files in this directory.

## How it works:
1. When building the Docker container (`make push` or `docker build`), all files in this directory are copied to `/app/rules/`.
2. At worker startup, `YaraScanner` automatically loads and compiles every `*.yar` and `*.yara` file found in `/app/rules/` (or the path set by `YARA_RULES_DIR`).
3. Each rule file is compiled into its own isolated namespace (named after the file stem) alongside the built-in DFIR rules.
4. For forensic reproducibility and audit compliance (ISO 17025 / ASTM E2678), the cryptographic SHA-256 hash of every loaded rule file is logged into `chain_of_custody.json` under `sbom.yara_ruleset_sha256`.

## Adding Rules from External Repositories
You can clone or download external threat intelligence rulesets directly into this folder:
- **Signature-Base (Florian Roth)**: https://github.com/Neo23x0/signature-base
- **YARA-Rules Project**: https://github.com/Yara-Rules/rules
- **ReversingLabs YARA**: https://github.com/reversinglabs/reversinglabs-yara-rules
