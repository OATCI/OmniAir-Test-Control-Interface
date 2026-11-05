# OmniAir OmniTap — Universal V2X/A2X Capture Metadata Profile

## Purpose
OmniTap is the extensible, technology-neutral metadata profile for vehicle-to-everything (V2X) and aircraft-to-everything (A2X) packet captures (referred to collectively in this specification as V2X/A2X). It is designed as the definitive common representation for capture context, radio observations, packet metadata, and delayed analysis across V2X/A2X technologies. Its data types are written in Abstract Syntax Notation One (ASN.1) and encoded with the Canonical Octet Encoding Rules (COER, ITU-T X.696; decodable by any standard OER or COER decoder). The native packet bytes stay unchanged in the standard pcapng Enhanced Packet Block (EPB), so OmniTap adds universal V2X/A2X metadata without defining a new capture-file format.

It covers LTE-V2X and NR-V2X (3GPP PC5 sidelink, including 3GPP Release 18+ A2X direct sidelink services), ETSI ITS-G5 (IEEE 802.11p), ITS Connect (ARIB STD-T109), and network V2X/A2X carried over IP.

**Release readiness.** The specification is being completed for broader OmniAir review and approval. The production Private Enterprise Number (PEN), LinkTypes, and OID root still require assignment (see `00-OmniTap-Registrations.md`). These are release dependencies, not limitations on OmniTap's intended scope or permanence.

## Documents in this repository
| File | What it is for |
|------|----------------|
| `00-OmniTap-README.md` | This file. Overview of the profile, the two stream flavors (`OmniTap` and `OmniTap-Lua`), and the repository. Start here. |
| `00-OmniTap-Requirements.md` | Goals and normative data principles; why `OmniTap` (Native) uses EPB Custom Binary Option `2989` and why `OmniTap-Lua` exists for stock Wireshark Lua; how packets are identified (`epb_packetid`); dissector requirements; why COER/OER; the validation release gate. |
| `00-OmniTap-Architecture.md` | How the pieces fit together: `OmniTap` vs. `OmniTap-Lua` block layouts, Custom Block and Option identity, the correlation contract, monolithic vs. split driver/HLOS producer architectures (and the 6-line C toggle for `OmniTap-Lua`), how common capture-file tools treat both flavors (tested), native packet preservation, and how future radio access technologies are added. |
| `00-OmniTap-Glossary.md` | Definitions of the terms, abbreviations, and identifier conventions used in the documents and modules, with references. |
| `00-OmniTap-Registrations.md` | Action plan for the identifiers OmniAir must obtain before release: the IANA PEN and the pcapng LinkTypes. Includes owners and status tracking. |
| `01-omnitap-asn1-style.md` | Source style for the ASN.1 modules: layout, naming, comments, extensibility, and validation. |

The ASN.1 modules are the normative definition of the data. The Markdown documents explain and constrain their use. If a document and a module disagree, the module governs and the document is to be corrected.

## Two stream flavors: `OmniTap` (Native) and `OmniTap-Lua`
OmniTap defines **one ASN.1 schema (`00-OmniTap-Objects.asn`) and one byte-aligned `COER(OmniTapObject)` encoding**, with two losslessly convertible pcapng stream flavors:

1. **`OmniTap` (Native — primary normative format):**
   * Session-level **`CaptureContext`**, per-interface **`InterfaceContext`**, and asynchronous **`SupplementalResult`** objects are carried in standalone copyable pcapng **Custom Blocks** (`block_type = 0x00000BAD`).
   * Per-packet **`PacketMetadata`** is carried **inside the Enhanced Packet Block (EPB)** it describes as a copyable **Custom Binary Option** (`opt_custom_binary_copy`, option code `2989` / `0x0BAD`), alongside `epb_packetid`.
   * **Why EPB Option `2989` is the main design:** It follows the IETF OPSAWG pcapng specification (section 3.5.1 for per-block custom data), keeps each packet and its `PacketMetadata` **atomically bound as a single frame** across `mergecap`, `editcap`, deduplication (`editcap -d`), and Wireshark GUI *Export Specified Packets* (zero orphan `PacketMetadata` blocks), and saves 8 octets of framing per packet. It is decoded directly by Wireshark or `tshark` built with the `asn2wrs`-generated OmniTap C dissector.
2. **`OmniTap-Lua` (convenience stream for older or unmodified stock Wireshark/TShark):**
   * Older or unmodified stock Wireshark/TShark installations that have not been recompiled with the `asn2wrs` OmniTap C dissector can still load a portable **Lua dissector (`.lua`)**. However, stock Wireshark's Lua API exposes standalone Custom Blocks (`0x00000BAD`) and does not expose EPB Custom Binary Options (`2989`).
   * Therefore, **the Lua-only dissector requires an `OmniTap-Lua` stream**, in which each EPB's `PacketMetadata` payload is unpacked into a standalone copyable **Custom Block (`0x00000BAD`)** immediately preceding the EPB.
   * **Always convertible with `scripts/OmniLuazer.py`:** You never lose compatibility by capturing in standard `OmniTap` (Native). The included Python tool **`scripts/OmniLuazer.py`** losslessly converts any `OmniTap` file to `OmniTap-Lua` (`--to-lua`) for the Lua dissector, or folds an `OmniTap-Lua` file back into native `OmniTap` (`--to-native`), in milliseconds without touching packet bytes, timestamps, or COER payloads.

### `OmniTap` (Native) organization (primary standard)
```text
SHB                                  Section Header Block (standard)
IDB  if_name, if_tsresol = 3/6/9     one per capture interface (standard)
Capture Context                      OmniTap Custom Block (0x00000BAD): the capture session
Interface Context                    OmniTap Custom Block (0x00000BAD): one per interface
EPB  epb_packetid + Option 2989      the unmodified packet + Packet Metadata inside EPB Option 2989
...
Supplemental Result                  OmniTap Custom Block (0x00000BAD), may come much later
```

### `OmniTap-Lua` organization (for stock Wireshark Lua dissector)
```text
SHB                                  Section Header Block (standard)
IDB  if_name, if_tsresol = 3/6/9     one per capture interface (standard)
Capture Context                      OmniTap Custom Block (0x00000BAD): the capture session
Interface Context                    OmniTap Custom Block (0x00000BAD): one per interface
Packet Metadata                      OmniTap Custom Block (0x00000BAD), SHOULD sit just before its packet
EPB  epb_packetid                    the packet, byte for byte as captured (standard)
...
Supplemental Result                  OmniTap Custom Block (0x00000BAD), may come much later
```

- Every OmniTap Custom Block (`0x00000BAD`) and EPB Custom Binary Option (`2989` / `0x0BAD`) uses the final profile owner's IANA PEN. **The production PEN has not yet been assigned.** Test data uses the documentation PEN 32473 (RFC 5612), which SHALL NOT be presented as an assigned PEN.
- The payload SHALL be `COER(OmniTapObject)` from `00-OmniTap-Objects.asn`: a 4-octet profile version prefix followed by the 1-octet body `CHOICE` tag (`0x80..0x83`) and body (capture context, interface context, packet metadata, or supplemental result).
- Native EPB packet bytes are never modified or prefixed by OmniTap.
- A producer SHALL write the Capture Context at the start of every file of a session, the first file included, and the Interface Context of each interface before that interface's first EPB in the file. It SHALL NOT restart `recordId` in a later file of the same session.

### Reference C99 producer header (`include/omnitap_coer.h`) and the 6-line `OmniTap-Lua` toggle
A producer (OBU, RSU, AVD, or capture agent) can include the reference dependency-free C99 header **`include/omnitap_coer.h`** to encode `COER(OmniTapObject)` buffers (`omnitap_coer_encode_capture_context`, `omnitap_coer_encode_packet_metadata`) without any external ASN.1 library or bit-stream state machine. Because both `OmniTap` (Native) and `OmniTap-Lua` write the exact same `COER(OmniTapObject)` byte buffer (`meta_buf`, `meta_len`), a producer that wishes to offer a runtime `OmniTap-Lua` output toggle alongside native `OmniTap` (`omnitap_write_packet` in `include/omnitap_coer.h`) only needs 6 lines of C when writing a packet:

```c
/* meta_buf (meta_len octets) holds COER(OmniTapObject) with body = packetMetadata (0x82) */
if (cfg->omnitap_lua_mode) {
    /* OmniTap-Lua: write standalone copyable Custom Block (0x00000BAD) immediately before EPB */
    pcapng_write_custom_block(fp, OMNITAP_PEN, meta_buf, meta_len);
    pcapng_write_epb(fp, if_id, ts_utc, pkt_bytes, pkt_len, epb_packetid, OMNITAP_PEN, NULL, 0);
} else {
    /* OmniTap Native (default): attach meta_buf to EPB as Custom Binary Option 2989 (0x0BAD) */
    pcapng_write_epb(fp, if_id, ts_utc, pkt_bytes, pkt_len, epb_packetid, OMNITAP_PEN, meta_buf, meta_len);
}
```

Implementing this flag on the capture device is completely optional—any standard `OmniTap` capture can be converted in post-processing at any time using `python scripts/OmniLuazer.py input.pcapng output.omnitap-lua.pcapng`.

## Packet association
Each EPB that has OmniTap Packet Metadata, or may be the target of a Supplemental Result, SHALL carry the standard pcapng `epb_packetid` option. It is a 64-bit number divided into two 32-bit halves:

`epb_packetid = sessionTag × 2^32 + recordId`

- `sessionTag` is the last four octets of the 128-bit `CaptureSessionId`, read as an unsigned big-endian number.
- `recordId` is the producer's packet counter within the capture session.

Association uses only this number, never block order, EPB position, frame number, or pcapng interface number, because merging, trimming, and filtering change those. If no EPB matches an OmniTap object, readers SHALL NOT guess and SHALL report the object as unassociated. The rationale and the limits are in `00-OmniTap-Requirements.md`.

- **Packet Metadata** carries its own `sessionTag` and `recordId`, so it names its packet without reading any EPB. Adjacency to its EPB is a convenience, not the association rule, and a chronological merge breaks it.
- **Supplemental Result** is matched by `sessionId` and `recordId`, and may be written later in the file.
- **Interface Context** is matched for each EPB: the context whose `sessionTag` equals the high 32 bits of the EPB's `epb_packetid` and whose `interfaceName` equals the `if_name` of the EPB's IDB. This matters because the default `mergecap` merge puts packets of two sessions on one IDB when both files name an interface alike. A producer SHALL write `epb_packetid` on every EPB, and `if_name` on every IDB, of an interface that has Interface Context.
- **Duplicates.** Identical duplicate objects count as one. Different objects that name the same packet are a conflict, which readers report without choosing.
- **One packet identifier is one observation.** When two devices capture the same on-air packet, each has its own session and its own identifier, and the two observations are kept apart. Readers SHALL NOT compare or merge metadata across sessions.

## Native packet bytes by radio access technology
| Technology | EPB packet data | LinkType |
|------------|-----------------|----------|
| LTE-V2X PC5 | Defined per technology; see `00-OmniTap-Registrations.md` | Not yet assigned |
| NR-V2X PC5 | Defined per technology; see `00-OmniTap-Registrations.md` | Not yet assigned |
| ETSI ITS-G5 (IEEE 802.11p) | Standard Radiotap header, then the IEEE 802.11 frame | `LINKTYPE_IEEE802_11_RADIOTAP` (127) |
| ITS Connect (ARIB STD-T109) | 24-octet MAC control field, then the LLC PDU (with SNAP). Not Radiotap. Whether the 4-octet frame check sequence is kept is still to be settled. | Not yet assigned |
| Network V2X (UDP, TCP, MQTT) | Native IP traffic | `LINKTYPE_ETHERNET` (1) or `LINKTYPE_RAW` (101) |

- **ETSI ITS-G5:** Radiotap remains authoritative for radio and physical-layer information, including the channel frequency and the half-rate (10 MHz) and quarter-rate (5 MHz) flags. OmniTap values for the same facts SHALL NOT contradict Radiotap and SHOULD be omitted. `21-03-OmniTap-RAT-ETSI-ITSG5.asn` is an extensible hook for information Radiotap cannot carry.
- **LTE-V2X and NR-V2X:** the Layer-2 source and destination IDs are always 24 bits (three octets, most significant octet first).
- **ITS Connect:** the Japanese V2X system, built on ARIB STD-T109 plus the ITS FORUM RC-010 extended layer. The schema names it `aribT109`, after the radio standard. Times inside ITS Connect messages are Japan Standard Time (UTC+9); they are not the EPB timestamp.
- **WAVE Service Advertisement (IEEE 1609.30).** OmniTap has no WSA-specific object. A WSA is decoded as an IEEE 1609 payload selected by Provider Service Identifier (PSID), also when it is carried over LTE-V2X.

## Time
EPB timestamps SHALL be POSIX UTC at millisecond, microsecond, or nanosecond resolution (IDB `if_tsresol` = 3, 6, or 9; readers treat an IDB without `if_tsresol` as 6, the pcapng microsecond default). OmniTap supplies clock-quality information, not a second packet timestamp or a selectable EPB epoch. Fields whose names end in `Us` are durations, not timestamps. A payload protocol that uses International Atomic Time (TAI), for example IEEE 1609.2, keeps its protocol-defined time interpretation.

## Position and radio observations
Packet Metadata carries at most one **observer location** and one **radio observation**. Neither is repeated for the two directions. The location is that of the capture platform, whether it received or sent the packet. The direction of the packet comes only from the `epb_flags` option of the EPB (Wireshark `frame.packet_flags_direction`), and OmniTap does not repeat it. Each field of the radio observation says whether it describes reception, transmission, or both.

- **Coordinate reference system.** A position names the system in which it is expressed: `wgs84`, `gcj02`, or `other`. It is deliberately not called a datum, because some systems warp the coordinates, and the warp need not be a two-dimensional shift. GCJ-02 shifts latitude and longitude only. The list can grow.
- **Limits.** Longitude uses the range of IEEE 1609.2, which includes +180 degrees and excludes -180 degrees. At most four antennas, numbered 0 to 3, can be described. Frequency can reach 100 GHz and bandwidth 100 MHz, which leaves room for future radios.
- **Where large numbers come from.** The 32-bit and 128-bit identifier widths were not invented for OmniTap. They come from pcapng and from the UUID format (RFC 9562). `00-OmniTap-Requirements.md`, section "Where the numeric widths come from", lists the source of every wide range and marks the ones that are OmniTap's own choice.

## Supplemental results
A Supplemental Result carries analysis that was not available when the EPB was recorded, such as IEEE 1609.2 security verification outcomes and SAE J3287 misbehavior observations.

- Each result names its producer (PEN, product name, and optional software version).
- `resultSequence` orders results from one producer: the higher value supersedes the lower. Results from different producers are kept side by side.
- An absent OPTIONAL value makes no assertion. A value of `unavailable` means the check was attempted but could not run or complete.

## Profile version and extensibility
Every `OmniTapObject` begins with a profile version of two integers (major and minor). In COER/OER, this is always encoded in the first four octets of the payload (`0x00` `OmniTapObject` preamble, `0x00` `OmniTapProfileVersion` preamble, 1-octet `major`, 1-octet `minor`), followed by the 1-octet `OmniTapObjectBody` `CHOICE` tag (`0x80..0x83`), and future major versions SHALL keep that prefix. A minor release only adds content behind extension markers. A reader SHALL NOT decode the body of a major version it does not implement.

All public `SEQUENCE`, `CHOICE`, and `ENUMERATED` types have ASN.1 extension markers. An object that has extension space carries a field named `optionalExtensions`, which holds up to two regional and up to two PEN-owned extension values. PEN-owned extensions may carry information such as manufacturer-private capabilities, proprietary diagnostics, calibration data, or tool-specific annotations. Extension values are opaque to base readers. Their `extensionType` is scoped by `ownerPen` or `regionalIdentifier`; it is not globally unique.

## Working with OmniTap files
OmniTap files are ordinary pcapng files:
- **In Wireshark/TShark compiled with the `asn2wrs` OmniTap C dissector:** Open **`OmniTap` (Native)** (or `OmniTap-Lua`) files directly. Each packet is a single frame with its `PacketMetadata` decoded from EPB Custom Binary Option `2989`.
- **In older or unmodified stock Wireshark/TShark using only the portable Lua dissector:** Convert the capture to **`OmniTap-Lua`** first with `python scripts/OmniLuazer.py input.pcapng output.omnitap-lua.pcapng`, then open `output.omnitap-lua.pcapng` with the Lua dissector loaded.

What common tools do to **`OmniTap` (Native)** and **`OmniTap-Lua`** files, as tested with Wireshark 4.6.9 (details in `00-OmniTap-Architecture.md`, section "Behavior of common tools"):

| Action | `OmniTap` (Native: EPB Option `2989`) | `OmniTap-Lua` (Custom Block `0x00000BAD`) |
|--------|---------------------------------------|-------------------------------------------|
| Save As, `mergecap`, `editcap` (rewrite), `reordercap`, `tshark -w` on a whole file | All kept (1 frame per packet) | All kept (2 frames per packet) |
| Export Specified Packets (selected, marked, or displayed), or `tshark -Y ... -w` | **`PacketMetadata` kept automatically** inside each exported EPB; Context/Result Custom Blocks kept when matched by display filter | **Lost, with no warning** unless the display filter also matches the Custom Blocks (see below) |
| `mergecap` default (chronological) | `PacketMetadata` stays inside its EPB | Kept, but most `PacketMetadata` Custom Blocks no longer sit beside their packet |
| `editcap -c` (split) | `PacketMetadata` stays with every EPB; Contexts in first file only | Contexts stay in the first file only |
| `editcap -d` (remove duplicates) | Duplicate packets **and** their `PacketMetadata` Option `2989` removed together (zero orphans) | Duplicate packets removed; their `PacketMetadata` Custom Blocks stay as orphans |

In `OmniTap-Lua`, Wireshark counts each Custom Block as a frame, so frame numbers include the OmniTap blocks. Do not use a frame number to identify a packet.

**With the dissector installed**, every OmniTap object and every packet that has `epb_packetid` carries the display-filter fields `omnitap.session_tag`, `omnitap.record_id`, and `omnitap.packet_id`; every OmniTap object also has `omnitap.kind`. One filter then selects a packet together with its standalone OmniTap Custom Blocks, and Export Specified Packets (Displayed) writes them all. Two examples, with your own values in place of the angle brackets:

```text
omnitap.session_tag == <tag>
omnitap.packet_id in {<id1>, <id2>} || (omnitap.session_tag == <tag> && omnitap.kind in {"capture-context", "interface-context"})
```

The first selects one whole capture session, for example one vehicle's or aircraft's run out of a merged file. The second selects chosen packets with their metadata and results, plus the session's Capture Context and Interface Context, so the exported file stands on its own.

### Removing duplicates and cleaning orphan blocks in `OmniTap-Lua`
`editcap -d` compares the packet bytes only, over a window of the last 5 packets by default, and keeps the first copy.
- On an **`OmniTap` (Native)** file, removing a duplicate EPB automatically removes its embedded `PacketMetadata` Option `2989`.
- On an **`OmniTap-Lua`** file, `editcap -d` removes the duplicate EPB but leaves the standalone `PacketMetadata` Custom Block behind as an **orphan** (which readers report as unassociated). Running `python scripts/OmniLuazer.py --clean-orphans input.omnitap-lua.pcapng cleaned.omnitap-lua.pcapng` (or converting back to native with `--to-native --clean-orphans`) strips any orphan `PacketMetadata` or `SupplementalResult` Custom Blocks whose target EPB is no longer in the file.

## ASN.1 modules (`asn/`)
All 12 normative `.asn` modules live in the **`asn/`** subdirectory. Module object identifiers (OIDs) have the form `{ 1 3 6 1 4 1 32473 omniTap(1) <name>(NN) major-version-1(1) minor-version-0(0) }`, where `NN` equals the two-digit filename prefix. The four technology modules share the arc `rat(21)`.

| File | Scope |
|------|-------|
| `asn/00-OmniTap-Objects.asn` | Top-level envelope: profile version, capture context, and the choice of object kinds |
| `asn/10-OmniTap-Interface-Context.asn` | Per-interface context, matched for each EPB by session tag and interface name |
| `asn/11-OmniTap-Time.asn` | UTC clock quality and timestamp reference points |
| `asn/12-OmniTap-Observer.asn` | Observer location and coordinate reference system, antennas, and one radio observation |
| `asn/20-OmniTap-Packet-Metadata.asn` | Per-EPB correlated metadata, with one branch per technology |
| `asn/21-01-OmniTap-RAT-LTE-V2X.asn` | LTE-V2X PC5 (V2X and Release 18+ A2X): addressing, SCI format 1, timing, lower-layer summary, RRC configuration snapshot |
| `asn/21-02-OmniTap-RAT-NR-V2X.asn` | NR-V2X PC5 (V2X and Release 18+ A2X): slot timing, addressing, 1st- and 2nd-stage SCI, PSFCH feedback, Mode 2 diagnostics, lower-layer summary, RRC configuration snapshot |
| `asn/21-03-OmniTap-RAT-ETSI-ITSG5.asn` | ETSI ITS-G5 (IEEE 802.11p): currently an empty extension hook |
| `asn/21-04-OmniTap-RAT-ARIB-T109.asn` | ITS Connect (ARIB STD-T109): currently an empty extension hook |
| `asn/30-OmniTap-Supplemental-Result.asn` | Late correlated analysis: security verification, misbehavior observations, producer identity |
| `asn/40-OmniTap-Extensions.asn` | The `optionalExtensions` container: regional and third-party extension values |
| `asn/90-OmniTap-Common.asn` | Common identifiers (session, record, interface name), V2X/A2X technology, payload classification, and the source of each numeric width |

## Tools, dissectors, reference C header, and sample files
All helper, conversion, and validation scripts live in **`scripts/`**, dissectors in **`dissector/`**, the reference C99 COER encoder in **`include/`**, and reference captures in **`samples/`**:

| File | What it is for |
|------|----------------|
| `scripts/OmniLuazer.py` | Lossless bidirectional converter between **`OmniTap` (Native)** (EPB Option `2989`) and **`OmniTap-Lua`** (Custom Block `0x00000BAD`) for stock Wireshark Lua dissectors (`--to-lua`, `--to-native`, `--clean-orphans`, `--self-test`). |
| `scripts/OmniTap-Generate-Samples.py` | Compiles all 12 ASN.1 modules in OER/COER mode and generates the reference multi-RAT V2X/A2X sample captures in `samples/` (`--self-test`). |
| `scripts/OmniTap-Validate.py` | Repository checks and the local validation run (see Validation). |
| `scripts/OmniTap-Survival-Test.py` | Builds test files in both **`OmniTap` (Native)** and **`OmniTap-Lua`** flavors and runs `mergecap`, `editcap`, `reordercap`, and `tshark` on them, reproducing the results in `00-OmniTap-Architecture.md`. |
| `scripts/OmniTap-Setup.py` | One-time setup: installs the open-source ASN.1 library and downloads the Wireshark `asn2wrs` generator that matches the installed Wireshark into `tools/` (third-party, not part of the profile). |
| `dissector/omnitap.lua` | Reference Wireshark Lua dissector for **`OmniTap-Lua`** streams; decodes `COER(OmniTapObject)` Custom Blocks and publishes `omnitap.kind`, `omnitap.session_tag`, `omnitap.record_id`, `omnitap.packet_id`, and context/result fields. |
| `dissector/asn2wrs/` | Conformance file (`omnitap.cnf`) and template (`packet-omnitap-template.c`) for the native `asn2wrs -e` C dissector. |
| `include/omnitap_coer.h` | Reference dependency-free C99 header-only COER encoder and pcapng writer supporting both `OmniTap` (Native) and `OmniTap-Lua`. |
| `samples/omnitap-reference-v2x-a2x.pcapng` | Reference multi-RAT V2X/A2X capture in **`OmniTap` (Native)** format (EPB Option `2989`) with real COER payloads (LTE-V2X, NR-V2X/A2X, ETSI ITS-G5, ITS Connect, and Supplemental Result). |
| `samples/omnitap-reference-v2x-a2x.omnitap-lua.pcapng` | The same reference capture converted via `scripts/OmniLuazer.py` into **`OmniTap-Lua`** format for `dissector/omnitap.lua`. |
| `omnitap.cmd` | ASN.1 compiler command file. Lists the modules in the required order. |
| `omnitap.a1sproj` | ASN.1 compiler project file. Lists the same modules. |

When an `.asn` file is added, renamed, or removed, update both module lists in the same change. Keep the filename order.

## Validation
Run once, then after every change to an ASN.1 module:

```text
python scripts/OmniTap-Setup.py
python scripts/OmniTap-Validate.py
python scripts/OmniLuazer.py --self-test
python scripts/OmniTap-Generate-Samples.py --self-test
```

`scripts/OmniTap-Validate.py` checks line length, module names and OIDs, `IMPORTS`, and extension markers. It compiles all modules together for OER/COER with an open-source library and generates OER dissector source with `asn2wrs`.

The release gate is stricter. Every module SHALL be checked with at least two independent ASN.1 compilers, each reporting zero errors and zero warnings, and SHALL also be processed successfully by `asn2wrs`. The script is supplementary and does not replace those checks.

## Open items
- Production PEN and the pcapng LinkTypes (`00-OmniTap-Registrations.md`); the per-technology EPB layout, including the ITS Connect frame check sequence, comes first.


