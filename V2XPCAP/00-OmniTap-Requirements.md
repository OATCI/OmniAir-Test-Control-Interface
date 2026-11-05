# OmniTap Requirements

## Goals
1. Use standard pcapng blocks and options; do not define a separate capture-file format.
2. Preserve one logical packet as one unmodified Enhanced Packet Block (EPB).
3. Encode all OmniTap objects in ASN.1 Canonical Octet Encoding Rules (COER, ITU-T X.696; decodable by any standard OER or COER decoder), owned by a Private Enterprise Number (PEN).
4. Use **EPB Custom Binary Option `2989` (`0x0BAD`)** as the primary **`OmniTap` (Native)** carriage for per-packet `PacketMetadata` (with session-level `CaptureContext`, `InterfaceContext`, and asynchronous `SupplementalResult` carried in standalone copyable Custom Blocks `0x00000BAD`), while providing the lossless **`OmniTap-Lua`** compatibility stream (all objects in Custom Blocks `0x00000BAD`) and the **`scripts/OmniLuazer.py`** converter for older or unmodified Wireshark/TShark installations using only the Lua dissector.
5. Support LTE-V2X and NR-V2X (3GPP PC5 sidelink for both V2X and Release 18+ A2X), ETSI ITS-G5 (IEEE 802.11p), ITS Connect (ARIB STD-T109), and typed future V2X/A2X radio access technology (RAT) additions.
6. Support late-arriving analysis through correlated Supplemental Results.
7. Be suitable both for a native C dissector generated with Wireshark's `asn2wrs` (which decodes `OmniTap` Native and `OmniTap-Lua`) and for a portable Wireshark Lua dissector (which decodes `OmniTap-Lua` on unmodified Wireshark builds).
8. Be fully extensible without opaque generic RAT fallbacks.
9. Survive common capture-file tools. OmniTap association SHALL still work after `mergecap`, `editcap`, and Wireshark filtering or Export Specified Packets. It SHALL rely only on data those tools preserve (`epb_packetid`, EPB Custom Binary Option `2989` in `OmniTap` Native, Custom Blocks `0x00000BAD`, and Interface Description Block (IDB) `if_name`), never on block order, frame number, or pcapng Interface ID.

## Normative data principles
- EPB timestamps SHALL be POSIX UTC at millisecond, microsecond, or nanosecond resolution: the `if_tsresol` option of an IDB SHALL be 3, 6, or 9 (readers treat an IDB without `if_tsresol` as 6, the pcapng microsecond default). Fields whose names end in `Us` are durations, not timestamps.
- An absent OPTIONAL field makes no assertion. It is not a numeric sentinel, false, zero, or unavailable indication.
- `recordId` SHALL be present for every Packet Metadata object and every Supplemental Result target. `sessionTag` SHALL be present in every Packet Metadata object, so that the object names its packet whether it is carried inside the EPB as Custom Binary Option `2989` (`OmniTap` Native) or as a standalone Custom Block (`OmniTap-Lua`).
- All public `SEQUENCE`, `CHOICE`, and `ENUMERATED` types SHALL include `...` extension markers.
- Base readers SHALL NOT interpret third-party `opaqueValue` content.
- Radio and physical-layer fields that standard Radiotap already carries (ETSI ITS-G5) SHALL NOT be duplicated in OmniTap ASN.1. Radiotap is authoritative for the ITS-G5 channel: its frequency field and its half-rate (10 MHz) and quarter-rate (5 MHz) channel flags. An OmniTap frequency or bandwidth for such a packet SHALL NOT contradict Radiotap and SHOULD be omitted.
- Packet direction SHALL NOT be repeated in OmniTap. It comes only from the `epb_flags` option of the EPB. Packet Metadata therefore carries one observer location and one radio observation, not one of each per direction.
- A position names its coordinate reference system (`wgs84`, `gcj02`, or `other`). The term is deliberately not "datum": a system may warp coordinates, and the warp need not be a two-dimensional shift.
- The RAT named by the `technology` field of an Interface Context and by the `technologyMetadata` alternative of the Packet Metadata of its packets SHALL be the same. A reader that finds a mismatch treats the Packet Metadata as authoritative for that packet and SHOULD report the mismatch.
- An object that has extension space carries it in a field named `optionalExtensions`.
- Layer-2 source and destination IDs of LTE-V2X and NR-V2X are always 24 bits (`OCTET STRING (SIZE(3))`, most significant octet first).
- Minimize OBU/RSU/AVD CPU overhead and dissector complexity while keeping wire size compact by encoding all OmniTap objects in byte-aligned ASN.1 COER (ITU-T X.696).

## Two stream flavors: `OmniTap` (Native) and `OmniTap-Lua`
Both stream flavors use the **exact same ASN.1 schema (`00-OmniTap-Objects.asn`) and identical `COER(OmniTapObject)` byte payloads**. They differ only in where per-packet `PacketMetadata` is placed in the pcapng container:

| Object kind | `OmniTap` (Native — primary standard) | `OmniTap-Lua` (Lua compatibility mode) |
|-------------|---------------------------------------|----------------------------------------|
| `CaptureContext` (`0x80`) | Standalone copyable Custom Block (`0x00000BAD`) | Standalone copyable Custom Block (`0x00000BAD`) |
| `InterfaceContext` (`0x81`) | Standalone copyable Custom Block (`0x00000BAD`) | Standalone copyable Custom Block (`0x00000BAD`) |
| `PacketMetadata` (`0x82`) | **Inside the EPB** as copyable **Custom Binary Option `2989` (`0x0BAD`)** | Standalone copyable Custom Block (`0x00000BAD`) preceding the EPB |
| `SupplementalResult` (`0x83`) | Standalone copyable Custom Block (`0x00000BAD`) | Standalone copyable Custom Block (`0x00000BAD`) |

### Why `OmniTap` (Native) uses EPB Custom Binary Option `2989`
1. **Standards alignment.** The IETF OPSAWG pcapng specification defines Custom Options (section 3.5.1) for custom data attached to a specific block (such as an EPB) and Custom Blocks (section 4.8) for standalone data that is not part of another block (such as session context or asynchronous late results).
2. **Atomic survival across capture tools.** When `PacketMetadata` rides inside the EPB as Custom Binary Option `2989`, `editcap`, `mergecap`, `reordercap`, `tshark`, and Wireshark GUI *Export Specified Packets* never separate a packet from its metadata. `editcap -d` removes duplicate EPBs together with their metadata (leaving zero orphan `PacketMetadata` blocks), and 1 packet equals 1 Wireshark frame number.
3. **Lower framing overhead.** An EPB Custom Binary Option adds 8 octets of framing (`option_code = 2989`, `option_length`, and 4-octet PEN), whereas a standalone Custom Block adds 16 octets of block framing (`block_type`, `total_length`, 4-octet PEN, and trailing `total_length`), saving 8 octets on every packet.

### Why `OmniTap-Lua` and `scripts/OmniLuazer.py` exist
Stock Wireshark/TShark installations that have not been compiled with the `asn2wrs`-generated OmniTap C dissector do not expose EPB Custom Binary Option `2989` to the Lua scripting API, whereas standalone Custom Blocks (`0x00000BAD`) are accessible to Lua.
- The **Lua-only dissector** therefore requires an **`OmniTap-Lua`** stream.
- The repository provides **`scripts/OmniLuazer.py`**, which losslessly converts any **`OmniTap` (Native)** file to **`OmniTap-Lua`** (`python scripts/OmniLuazer.py --to-lua input.pcapng output.omnitap-lua.pcapng`) and back (`--to-native`), and can strip orphan Custom Blocks (`--clean-orphans`).
- A producer that wishes to offer direct `OmniTap-Lua` output as an optional runtime flag only needs a 6-line C branch at the packet-write call (writing `meta_buf` into Custom Block `0x00000BAD` before the EPB instead of passing `meta_buf` as EPB Option `2989`; see `00-OmniTap-Architecture.md`).

## Packet identification: the epb_packetid split
Each EPB that has OmniTap metadata, or may be the target of a Supplemental Result, SHALL carry the standard pcapng `epb_packetid` option. It is one 64-bit number (Wireshark: `frame.packet_id`). OmniTap divides it into two 32-bit halves:

| Bits    | Field        | Meaning                                    | Source                                         |
|---------|--------------|--------------------------------------------|------------------------------------------------|
| 63..32  | `sessionTag` | Which capture session                      | Last 4 octets of `CaptureSessionId`, unsigned big-endian |
| 31..0   | `recordId`   | Which packet within that session           | Producer counter (1, 2, 3, ...)                |

`epb_packetid = sessionTag * 2^32 + recordId`. Example: a `CaptureSessionId` ending `7C 11 5E 90` gives `sessionTag` 0x7C115E90; with `recordId` 5, `epb_packetid` is 0x7C115E9000000005.

Rationale:
- **Why one packet number at all.** Block order, EPB ordinal, frame number, and pcapng Interface ID all change when files are merged, trimmed, or filtered. `epb_packetid` is stored inside the EPB and travels with it.
- **Why a session half.** Two captures can both number packets from 1. After a merge, `recordId` alone would be ambiguous. `sessionTag` keeps the packets of each capture distinct.
- **Why the last octets of the session ID.** In a UUIDv7 the leading octets are a timestamp, so sessions started close together share them. The trailing octets are random.
- **Why 32 bits each.** 32 bits of `recordId` allow 4,294,967,296 packets per session, about 24 days at 2,000 packets per second. Captures are not expected to approach a week, so a session SHOULD be restarted before it reaches the limit. 32 bits of `sessionTag` make a collision between two sessions about 1 in 4,294,967,296.
- **Collisions.** Supplemental Result and Capture Context carry the full 128-bit `sessionId`, which lets a reader resolve two sessions that share a `sessionTag`. Packet Metadata and Interface Context carry only the 32-bit `sessionTag`, so they cannot tell such sessions apart. That is accepted at a probability of about 1 in 4,294,967,296 per pair of sessions.
- **Interface Context.** An IDB has no session identifier, and tools can put packets of several sessions on one IDB (the default `mergecap` merge does so when two files name an interface alike). A reader therefore decides per EPB, not per IDB: an EPB uses the Interface Context whose `sessionTag` equals the high 32 bits of the EPB's `epb_packetid` and whose `interfaceName` equals the `if_name` of the EPB's IDB. Producers SHALL write `epb_packetid` on every EPB, and `if_name` on every IDB, of an interface that has Interface Context.
- **Reader behavior.** If no EPB matches an OmniTap object, readers SHALL NOT guess; they report the object as unassociated.
- **One identifier, one observation.** A packet identifier names a packet as one capture session observed it. Two devices that capture the same on-air packet have two sessions and two identifiers, and their metadata is kept apart. Readers SHALL NOT compare or merge metadata across sessions.
- **Duplicates.** In `OmniTap` (Native), `editcap -d` removes duplicate EPBs together with their embedded `PacketMetadata` Option `2989`. In `OmniTap-Lua`, `editcap -d` removes duplicate EPBs but leaves duplicate Custom Blocks, and merging a file with itself duplicates both. Objects that name the same packet and have byte-for-byte identical COER payloads are one object. Objects that name the same packet but differ are conflicting: readers SHALL NOT choose between them and SHALL report the conflict. EPBs with one `epb_packetid` are one packet only if their packet data and timestamps are identical; otherwise the identifier is ambiguous.
- **Contexts in every file.** Tools that split or trim a file can leave later files without the contexts written earlier. A producer SHALL write the Capture Context at the start of every file of a session, the first file included, and the current Interface Context of every interface before the first EPB of that interface in the file. Producers SHALL NOT restart `recordId` in a later file of the same session. A file with no context for a packet makes no assertion about it.
- **Position in the file.** Association never depends on where a block sits, because every OmniTap object carries explicit linkage fields. In `OmniTap-Lua` streams, a producer or `scripts/OmniLuazer.py` SHOULD write Packet Metadata immediately before the EPB it describes, which helps people reading the file. A reader SHALL NOT require that position and SHALL NOT use it to settle a missing or ambiguous match.

## Reader (dissector) requirements
OmniTap defines two reader tiers:
- The **native C dissector** generated with Wireshark's `asn2wrs`, which decodes both **`OmniTap` (Native)** (reading `PacketMetadata` from EPB Custom Binary Option `2989` and Contexts/Supplemental Results from Custom Blocks `0x00000BAD`) and **`OmniTap-Lua`**.
- The **portable Lua dissector** for older or unmodified Wireshark/TShark installations, which decodes **`OmniTap-Lua`** streams (produced directly or converted via `python scripts/OmniLuazer.py`).

Both dissectors SHALL meet the following:

1. **Registration.** Register for the OmniTap PEN in Wireshark's `pcapng_custom_block` dissector table (and, in the compiled `asn2wrs` C dissector, for EPB Custom Binary Option `2989` with the OmniTap PEN).
2. **Filter fields.** Publish these display-filter fields:

| Field | Set on | Meaning |
|-------|--------|---------|
| `omnitap.kind` | every OmniTap object | Object kind: capture context, interface context, packet metadata, or supplemental result |
| `omnitap.session_tag` | every OmniTap object, and every EPB that has `epb_packetid` | 32-bit session tag. For a Capture Context or a Supplemental Result it is the last four octets of `sessionId`. |
| `omnitap.record_id` | Packet Metadata, Supplemental Result, and every EPB that has `epb_packetid` | 32-bit record identifier |
| `omnitap.packet_id` | Packet Metadata, Supplemental Result, and every EPB that has `epb_packetid` | 64-bit packet identifier, `session_tag * 2^32 + record_id` |

3. **Self-contained values.** Compute each value from the object's own content (or, for an EPB, from its `epb_packetid`), never from other frames. Wireshark dissects frames out of order and again for filtering and export, so a value that depends on dissection order is wrong.
4. **Associations.** Resolve Interface Context per EPB (see "Packet identification"), apply the duplicate rules, and display unassociated or conflicting objects as such.
5. **Documentation.** The README SHALL explain that the Lua-only dissector on unmodified Wireshark builds requires `OmniTap-Lua` (converted via `scripts/OmniLuazer.py`), that in `OmniTap` (Native) `PacketMetadata` travels automatically inside each exported EPB, and how display filters also retain session Context and Supplemental Result Custom Blocks during subset exports.

In `OmniTap-Lua` (or when also exporting standalone Context and Supplemental Result Custom Blocks in `OmniTap` Native), a single display filter selects packets together with their standalone OmniTap Custom Blocks, and Export Specified Packets (Displayed) writes them all:

```text
omnitap.packet_id in {<id2>, <id4>} || (omnitap.session_tag == <tag> && omnitap.kind in {"capture-context", "interface-context"})
```

## Where the numeric widths come from
OmniTap did not invent the large numbers in the schema. This table lists the wide ranges and says where each comes from. A row marked "OmniTap's choice" is not set by any other specification. Clause numbers refer to the documents named in the Glossary; their text is not reproduced here.

| Field or type | Range | Source |
|---------------|-------|--------|
| `CaptureSessionId` | 128 bits | A UUID, which is 128 bits long (RFC 9562). |
| `sessionTag`, `recordId` | 32 bits each | OmniTap's split of the 64-bit `epb_packetid` option (IETF OPSAWG pcapng specification, section 4.3). pcapng defines only the 64-bit value. |
| PEN fields (`ownerPen`, `pen`) | 32 bits | The Private Enterprise Number field of a Custom Block / Custom Option (IETF OPSAWG pcapng specification, sections 3.5.1 and 4.8). |
| `interfaceName` | 1 to 255 octets | OmniTap's choice. pcapng gives each option a 16-bit length (section 3.5). |
| `ElapsedTimeUs` | 32 bits, about 71.6 minutes | OmniTap's choice. The largest value means that long or longer. |
| `latitudeE7`, `longitudeE7` | -900000000 to 900000000, and -1799999999 to 1800000000 | The units and ranges of IEEE Std 1609.2-2025 `NinetyDegreeInt` and `OneEightyDegreeInt`, without their "unknown" values. |
| `altitudeDm` | -4096 to 32767 decimeters | OmniTap's choice: `-409.6 m` to `+3,276.7 m` (`10,750 ft`), aligned to a 2-octet signed 16-bit integer in COER for ground V2X and aerial A2X observers. |
| `speedCmPerSec`, `verticalSpeedCmPerSec` | 0 to 65535 cm/s, and -32768 to 32767 cm/s | OmniTap's choice: aligned to 2-octet unsigned/signed 16-bit integers in COER, covering ground V2X and aerial/UAV A2X observers. |
| `centerFrequencyKHz`, `bandwidthKHz` | up to 100 GHz, and 100 MHz | OmniTap's choice, set high so that future radios fit. |
| `uncertaintyNs` | 0 to 1,000,000,000 | OmniTap's choice (one second). |
| `contextGeneration`, `resultSequence` | 16 bits | OmniTap's choice. |
| `estimatedAirPropagationDelayNs` | 0 to 50,035 | OmniTap's choice: about 15 km at the speed of light. |

In COER (ITU-T X.696), constrained integer bounds determine whether a field encodes in 1, 2, 4, or 8 octets. Aligning ranges to natural 8-, 16-, or 32-bit boundaries maximizes dynamic range without adding wire bytes.

## Encoding requirement: ASN.1 COER (ITU-T X.696)
OmniTap objects SHALL be encoded using **ASN.1 Canonical Octet Encoding Rules (COER, ITU-T X.696)**. Every COER encoding is also a valid Basic OER encoding, so any standard OER or COER decoder can decode it.

Why COER was chosen over bit-packed UPER and generic TLV:
1. **OBU/RSU/AVD CPU and code-size efficiency.** Because every COER preamble, CHOICE tag, and constrained 8/16/32-bit integer is 100% byte-aligned, encoding a rich 25-field packet metadata structure takes ~112 RISC instructions (`memcpy` + byte swaps) and ~2 KB of dependency-free C code, compared to ~650–800 shift/mask instructions for bit-level UPER—about a **6.5x CPU reduction** on resource-constrained embedded V2X/A2X processors.
2. **Dissector simplicity and security.** Byte alignment eliminates arbitrary bit-offset parsing errors, makes hex-dump inspection trivial (`00 00 01 00 82 ...`), and compiles cleanly through `asn2wrs -e` (OER mode).
3. **Compact storage.** For a representative 25-field LTE-V2X `PacketMetadata` object, COER is only **12 octets larger than UPER** (`62 B` vs. `50 B` raw ASN.1 payload) while remaining ~35–45 octets smaller than generic TLV (`95–105 B`). Furthermore, carrying `PacketMetadata` in EPB Custom Binary Option `2989` (`OmniTap` Native) saves **8 octets of pcapng framing per packet** compared to a standalone Custom Block:

| Per-packet `PacketMetadata` size (25-field rich packet) | `OmniTap` Native (EPB Option `2989`, COER) | `OmniTap-Lua` (Custom Block `0x00000BAD`, COER) | Compact byte-aligned TLV (Custom Block) |
|---------------------------------------------------------|-------------------------------------------:|------------------------------------------------:|----------------------------------------:|
| ASN.1 payload                                           |                                       62 B |                                            62 B |                                95–105 B |
| Padding to 32-bit boundary                              |                                        2 B |                                             2 B |                                   0–3 B |
| pcapng framing (Option `2989` = 8 B; Custom Block = 16 B)|                                        8 B |                                            16 B |                                    16 B |
| **Total per packet**                                    |                                   **72 B** |                                        **80 B** |                            **112–124 B**|

## ASN.1 constructs OmniTap does not use
Wireshark's `asn2wrs` does not support all of ASN.1 (Wireshark Developer's Guide, section "Hints For Using Asn2wrs"). A native Wireshark dissector generated from the published schema is a requirement, so OmniTap deliberately restricts itself to constructs `asn2wrs` handles. This is stricter than requiring formally valid ASN.1.

| Construct | OmniTap rule | Why |
|-----------|--------------|-----|
| `COMPONENTS OF` | SHALL NOT be used. Write the fields out. | `asn2wrs` does not support it. |
| Parameterized types and parameterized assignments (for example `Name{Parameter}`) | SHALL NOT be used. Use concrete values. | `asn2wrs` does not support them. |
| Tagged assignments (for example `[APPLICATION 30] IMPLICIT INTEGER`) | SHALL NOT be used. | The guide documents a code-generation defect. Every module uses `AUTOMATIC TAGS` and no explicit tags. |
| Information object classes, open types, and `ANY` | Not used in this specification. | Rewriting them by hand is required for `asn2wrs`. The extension model uses `opaqueValue` octets. |

- **CHOICE fields.** OmniTap has two `CHOICE` types used as `SEQUENCE` fields: `OmniTapObjectBody` and `TechnologyMetadata`. `asn2wrs` accepts both without warnings.
- **Check.** A search of all 12 modules finds none of the excluded constructs. The `asn2wrs` step of the release gate would also fail on an unsupported construct, because the gate treats any warning as a failure.

## ASN.1 validation release gate
Every OmniTap ASN.1 module SHALL be checked with at least two independent ASN.1 compilers (commercial and/or open source), each reporting zero errors and zero warnings under its strictest available syntax and semantic checking.

Every module SHALL also be processed successfully by the Wireshark `asn2wrs` dissector generator (`-e` OER mode), with no warnings. This step is mandatory: it confirms that a native Wireshark dissector can be generated from the published schema.

Repository linting (`scripts/OmniTap-Validate.py`) is supplementary and does not replace either check.

## Identifier placeholders
The Private Enterprise Number 32473 and the OID root `1.3.6.1.4.1.32473` are documentation placeholders (RFC 5612). They SHALL be replaced with identifiers assigned to the final profile owner before public release, and SHALL NOT appear in production files. No placeholder identifier may be represented as an assigned production identifier. The action plan is in `00-OmniTap-Registrations.md`.

