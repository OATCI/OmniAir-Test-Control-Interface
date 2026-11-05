# OmniTap Reference Sample Captures (`samples/`)

This directory contains reference multi-RAT V2X/A2X `.pcapng` captures containing real **ASN.1 COER (`COER(OmniTapObject)`)** payloads encoded from the 12 normative OmniTap ASN.1 modules.

## Files

| File | Flavor | Size | Description |
|------|--------|------|-------------|
| `omnitap-reference-v2x-a2x.pcapng` | **`OmniTap` (Native)** | `1,988 B` | **Primary standard format.** Per-packet `PacketMetadata` is carried inside each Enhanced Packet Block (EPB) as copyable Custom Binary Option `2989` (`0x0BAD`). Contains 1 `CaptureContext`, 4 `InterfaceContext` blocks, 4 EPBs with Option `2989`, and 1 late `SupplementalResult` Custom Block. |
| `omnitap-reference-v2x-a2x.omnitap-lua.pcapng` | **`OmniTap-Lua`** | `2,020 B` | **Lua-compatible format.** Produced by running `python scripts/OmniLuazer.py` on the native file above. Unpacks each EPB's Option `2989` into a standalone copyable Custom Block (`0x00000BAD`) immediately preceding the EPB so stock Wireshark/TShark can decode it with `dissector/omnitap.lua`. |

## What is inside the reference capture

Both files represent the exact same capture session (`sessionId = 018f4a20-0000-7000-8000-00007c115e90`, `sessionTag = 0x7c115e90`):

1. **`CaptureContext` (`0x00000BAD`)**: Session UUID, test campaign details, test case ID (`OAC-OMNITAP-REF-001`), and scenario description.
2. **Four IDBs and `InterfaceContext` blocks (`0x00000BAD`)**:
   - `pc5-lte0` (`lteV2x`, 5.915 GHz, 10 MHz, Release 16 RRC configuration snapshot, dual roof-fin antennas)
   - `pc5-nr0` (`nrV2x`, 5.905 GHz, 20 MHz, Release 18 A2X/V2X RRC configuration snapshot)
   - `its-g5-0` (`etsiItsG5`, IEEE 802.11p Radiotap)
   - `arib-t109-0` (`aribT109`, 760 MHz, 10 MHz ITS Connect)
3. **Four Packets (`recordId = 1..4`)**:
   - **Record 1 (`pc5-lte0`, RX):** LTE-V2X PC5 packet with WGS-84 observer position/motion, dual-antenna RSSI/RSRP/RSRQ/SINR, CBR, SCI Format 1, and lower-layer HARQ/RLC summary.
   - **Record 2 (`pc5-nr0`, TX):** NR-V2X / 3GPP Release 18 A2X PC5 packet from an aerial observer at `120.0 m` altitude (`altitudeDm = 1200`) climbing at `3.50 m/s`, with 1st-stage SCI, 2nd-stage SCI (`sciFormat2B` with zone ID and range requirement), PSFCH feedback, and Mode 2 TX sensing diagnostics.
   - **Record 3 (`its-g5-0`, RX):** ETSI ITS-G5 frame with Radiotap header + IEEE 802.11p QoS Data + GeoNetworking/BTP/CAM.
   - **Record 4 (`arib-t109-0`, RX):** ITS Connect frame with ARIB STD-T109 24-octet MAC control header + LLC/SNAP.
4. **`SupplementalResult` (`0x00000BAD`)**: Asynchronous IEEE 1609.2 security verification (`passed` / `success`) and SAE J3287 consistency/relevance/misbehavior checks referencing `(sessionId, recordId = 1)`.

## Regenerating the samples

```text
python scripts/OmniTap-Generate-Samples.py
```
