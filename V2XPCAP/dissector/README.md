# OmniTap Wireshark Dissectors (`dissector/`)

This directory contains the reference Wireshark dissectors for OmniTap V2X/A2X captures:

| Path | Target Stream Flavor | Description |
|------|----------------------|-------------|
| `omnitap.lua` | **`OmniTap-Lua`** (Custom Block `0x00000BAD`) | Portable Lua dissector for unmodified stock Wireshark/TShark installations. Decodes `COER(OmniTapObject)` Custom Blocks (`CaptureContext`, `InterfaceContext`, `PacketMetadata`, `SupplementalResult`) and attaches a postdissector that publishes `omnitap.session_tag`, `omnitap.record_id`, and `omnitap.packet_id` on every EPB with `epb_packetid`. |
| `asn2wrs/omnitap.cnf`<br>`asn2wrs/packet-omnitap-template.c` | **`OmniTap` (Native)** (EPB Option `2989`) and **`OmniTap-Lua`** (Custom Block `0x00000BAD`) | Conformance file and C template for generating the native Wireshark C OER/COER dissector (`packet-omnitap.c`) from the 12 normative `.asn` modules using Wireshark's `asn2wrs.py -e`. |

## Using `omnitap.lua` with Stock Wireshark or TShark

Unmodified stock Wireshark/TShark builds expose standalone pcapng Custom Blocks (`0x00000BAD`) to Lua, but do not expose EPB Custom Binary Options (`2989`).

1. If your capture is in standard **`OmniTap` (Native)** format, convert it to **`OmniTap-Lua`** using `scripts/OmniLuazer.py`:
   ```text
   python scripts/OmniLuazer.py input.pcapng output.omnitap-lua.pcapng
   ```
2. Open or inspect the `.omnitap-lua.pcapng` file with `dissector/omnitap.lua` loaded:
   ```text
   tshark -X lua_script:dissector/omnitap.lua -r samples/omnitap-reference-v2x-a2x.omnitap-lua.pcapng -V
   ```

## Display-Filter Fields Published by `omnitap.lua`

- `omnitap.kind` (`"capture-context"`, `"interface-context"`, `"packet-metadata"`, `"supplemental-result"`)
- `omnitap.session_tag` (32-bit hex session tag, derived from the low 32 bits of `sessionId` or `epb_packetid`)
- `omnitap.record_id` (32-bit packet counter within the session)
- `omnitap.packet_id` (64-bit correlation key `(session_tag << 32) | record_id`, matching `frame.packet_id`)
- `omnitap.version.major`, `omnitap.version.minor`
- `omnitap.session_id`, `omnitap.test_campaign_details`, `omnitap.test_case_id`, `omnitap.scenario_name`
- `omnitap.interface_name`, `omnitap.context_generation`, `omnitap.technology`
- `omnitap.producer_pen`, `omnitap.producer_name`, `omnitap.producer_version`, `omnitap.result_sequence`

## Generating the Native C Dissector with `asn2wrs`

`python scripts/OmniTap-Validate.py` automatically runs `tools/wireshark/asn2wrs.py -e` against all 12 ASN.1 modules on every validation run and requires zero warnings.
