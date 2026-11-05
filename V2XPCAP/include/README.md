# OmniTap Reference Producer C99 Header (`include/`)

This directory provides a dependency-free, header-only C99 reference implementation (`omnitap_coer.h`) for **producers** (On-Board Units, Roadside Units, Aerial V2X Devices, and test/capture agents).

## Why this header exists

OmniTap uses **ASN.1 Canonical Octet Encoding Rules (`COER`, ITU-T X.696)** because every integer, length determinant, and `CHOICE` tag is byte-aligned (`1`, `2`, `4`, or `8` octets). That eliminates bit-stream state machines and allows embedded C/C++ firmware to serialize `COER(OmniTapObject)` payloads in a few dozen instructions with zero external library dependencies.

## Contents

| File | Description |
|------|-------------|
| `omnitap_coer.h` | Header-only C99 encoder for `OmniTapObject` (`CaptureContext` and `PacketMetadata` with 3D WGS-84 V2X/A2X observer position and radio frequency/bandwidth) plus standard pcapng Custom Block (`0x00000BAD`) and Enhanced Packet Block (`EPB`) writers (`omnitap_write_packet`). |

## Supporting `OmniTap` (Native) and `OmniTap-Lua`

`omnitap_write_packet(...)` in `omnitap_coer.h` implements both OmniTap stream flavors using the exact same `COER(OmniTapObject)` byte buffer (`meta_buf`, `meta_len`):

- **`omnitap_lua_mode == 0` (`OmniTap` Native, default):** Attaches `meta_buf` directly inside the packet's Enhanced Packet Block (EPB) as copyable Custom Binary Option `2989` (`0x0BAD`). This keeps packet and metadata atomically bound through `editcap`, `mergecap`, `editcap -d`, and Wireshark GUI packet exports.
- **`omnitap_lua_mode != 0` (`OmniTap-Lua`):** Writes `meta_buf` as a standalone copyable Custom Block (`0x00000BAD`) immediately before the EPB for direct inspection in older or unmodified stock Wireshark installations using only `dissector/omnitap.lua`.

Producers only need to emit **`OmniTap` (Native)**; any native capture can be converted losslessly to `OmniTap-Lua` (and back) in post-processing using `python scripts/OmniLuazer.py`.

## PEN Note

`OMNITAP_PEN_PLACEHOLDER` (`32473`) is the RFC 5612 documentation Private Enterprise Number used for development and testing until the production PEN is assigned (see `../00-OmniTap-Registrations.md`).
