# OmniTap Public Tooling (`scripts/`)

This directory contains the public Python utilities for validating the OmniTap ASN.1 modules, converting between **`OmniTap` (Native)** and **`OmniTap-Lua`** streams, generating reference COER sample captures, and testing pcapng container survival across Wireshark CLI tools.

## Scripts

| Script | Purpose |
|--------|---------|
| `OmniLuazer.py` | Lossless bidirectional converter between **`OmniTap` (Native)** (EPB Custom Binary Option `2989`) and **`OmniTap-Lua`** (standalone Custom Block `0x00000BAD`) for stock Wireshark Lua dissectors (`--to-lua`, `--to-native`, `--clean-orphans`, `--self-test`). |
| `OmniTap-Generate-Samples.py` | Compiles all 12 normative `.asn` modules in OER/COER mode and generates the reference multi-RAT V2X/A2X captures in `samples/` (`--self-test`). |
| `OmniTap-Validate.py` | Public repository validator: checks line length, ASN.1 naming and style rules, module OIDs, `IMPORTS`, extension markers, joint `asn1tools` OER/COER compilation, and zero-warning Wireshark `asn2wrs.py -e` dissector generation. |
| `OmniTap-Survival-Test.py` | Builds test `.pcapng` files in both **`OmniTap` (Native)** and **`OmniTap-Lua`** flavors and runs `mergecap`, `editcap`, `reordercap`, and `tshark` on them to verify metadata and `epb_packetid` survival. |
| `OmniTap-Setup.py` | One-time developer setup: installs `asn1tools` and downloads the matching Wireshark `asn2wrs.py` generator into `tools/` (ignored by git). |
