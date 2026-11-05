# OmniTap Architecture

## File and block layout: `OmniTap` (Native) vs. `OmniTap-Lua`
An OmniTap file is an ordinary pcapng file. OmniTap leaves every standard block and native packet byte unchanged, and defines two losslessly convertible stream carriage flavors that share the **exact same `COER(OmniTapObject)` ASN.1 payloads**:

1. **`OmniTap` (Native — primary normative format):**
   * `CaptureContext`, `InterfaceContext`, and asynchronous `SupplementalResult` objects are carried in copyable pcapng **Custom Blocks** (`block_type = 0x00000BAD`).
   * Per-packet `PacketMetadata` is carried **inside the Enhanced Packet Block (EPB)** it describes as a copyable **Custom Binary Option** (`opt_custom_binary_copy`, option code `2989` / `0x0BAD`), alongside `epb_packetid`.
   * This follows the IETF OPSAWG pcapng specification (section 3.5.1 for per-block custom options and section 4.8 for standalone custom blocks), keeps each packet and its metadata atomically bound as a single frame across `mergecap`, `editcap`, deduplication (`editcap -d`), and Wireshark GUI packet exports, and saves 8 octets of block framing per packet. It is decoded directly by Wireshark or `tshark` compiled with the `asn2wrs`-generated OmniTap C dissector.
2. **`OmniTap-Lua` (Lua compatibility stream for older or unmodified stock Wireshark/TShark):**
   * Stock Wireshark's Lua API exposes standalone Custom Blocks (`0x00000BAD`) to a `.lua` dissector script, but does not expose EPB Custom Binary Options (`2989`).
   * For convenience on older or unmodified Wireshark/TShark installations that have not been compiled with the `asn2wrs` OmniTap C dissector, `OmniTap-Lua` unpacks each EPB's `PacketMetadata` option payload into a standalone copyable **Custom Block** (`0x00000BAD`) immediately preceding the EPB.
   * **Lossless conversion (`scripts/OmniLuazer.py`):** The repository provides `scripts/OmniLuazer.py`, which converts any `OmniTap` file to `OmniTap-Lua` (`--to-lua`) or folds an `OmniTap-Lua` file back into `OmniTap` (`--to-native`) without altering packet bytes, timestamps, or COER payloads.

### `OmniTap` (Native) layout (recommended default)
```text
pcapng Section
├─ Section Header Block (standard)
├─ OmniTap Capture-Context Custom Block (0x00000BAD, required in every file)
│  └─ COER(OmniTapObject: body = capture)
├─ Interface Description Block (standard)
├─ OmniTap Interface-Context Custom Block (0x00000BAD)
│  └─ COER(OmniTapObject: body = interfaceContext)
├─ Enhanced Packet Block (standard)
│  ├─ UTC timestamp + unmodified native packet bytes
│  ├─ epb_packetid option (option code 5)
│  └─ Custom Binary Option 2989 (0x0BAD): PEN + COER(OmniTapObject: body = packetMetadata)
└─ OmniTap Supplemental-Result Custom Block (0x00000BAD, zero or more, later)
   └─ COER(OmniTapObject: body = supplementalResult)
```

### `OmniTap-Lua` compatibility layout (for stock Wireshark Lua dissector)
```text
pcapng Section
├─ Section Header Block (standard)
├─ OmniTap Capture-Context Custom Block (0x00000BAD, required in every file)
│  └─ COER(OmniTapObject: body = capture)
├─ Interface Description Block (standard)
├─ OmniTap Interface-Context Custom Block (0x00000BAD)
│  └─ COER(OmniTapObject: body = interfaceContext)
├─ OmniTap Packet-Metadata Custom Block (0x00000BAD)
│  └─ COER(OmniTapObject: body = packetMetadata)
├─ Enhanced Packet Block (standard)
│  └─ UTC timestamp + unmodified native packet bytes + epb_packetid option
└─ OmniTap Supplemental-Result Custom Block (0x00000BAD, zero or more, later)
   └─ COER(OmniTapObject: body = supplementalResult)
```

Every OmniTap payload—whether in a Custom Block (`0x00000BAD`) or an EPB Custom Binary Option (`2989`)—is one `OmniTapObject` encoded in Canonical Octet Encoding Rules (COER, ITU-T X.696; decodable by any standard OER or COER decoder): a 4-octet profile version prefix (`0x00` `OmniTapObject` preamble, `0x00` `OmniTapProfileVersion` preamble, 1-octet `major`, 1-octet `minor`) followed by the 1-octet `OmniTapObjectBody` `CHOICE` tag (`0x80..0x83`) and the body. A reader checks the major version first and does not decode the body of a major version it does not implement.

## Custom Block and Custom Binary Option identity
Every OmniTap Custom Block (block type `0x00000BAD`) and EPB Custom Binary Option (option code `2989` / `0x0BAD`) is identified by the final profile owner's 32-bit IANA Private Enterprise Number (PEN). **No production OmniTap PEN has been assigned.** Test data uses the documentation PEN 32473 (RFC 5612), which SHALL NOT be represented as an assigned OmniAir or IANA production PEN. The final owner must either use its assigned PEN or obtain one before release; see `00-OmniTap-Registrations.md`.

## Correlation contract
Association uses explicit fields stored inside the OmniTap objects and inside the EPB. It never uses block order, EPB position, frame number, or pcapng Interface ID, because merging, trimming, and filtering change those.

1. **Packet identifier.** Each EPB that has OmniTap metadata, or may be the target of a Supplemental Result, carries the standard `epb_packetid` option. Its 64 bits are `sessionTag` (high 32 bits) and `recordId` (low 32 bits). `sessionTag` is the last four octets of the 128-bit `CaptureSessionId`. Details and rationale are in `00-OmniTap-Requirements.md`.
2. **Packet Metadata** names its packet with `sessionTag` and `recordId`, so the object identifies its packet whether it rides inside the EPB as Custom Binary Option `2989` (`OmniTap` Native) or as a standalone Custom Block (`OmniTap-Lua`). In `OmniTap-Lua` streams, a producer or `scripts/OmniLuazer.py` SHOULD write the Custom Block immediately before the EPB it describes, which helps people reading the file; a reader SHALL NOT require that position and SHALL NOT use it to resolve a missing or ambiguous match.
3. **Supplemental Result** is written later, when result data was not available at capture time. It names its target with `sessionId` and `recordId`, so it may appear anywhere after the target in the section.
4. **Interface Context** is matched per EPB, not per IDB. An EPB uses the context whose `sessionTag` equals the high 32 bits of the EPB's `epb_packetid` and whose `interfaceName` equals the `if_name` of the IDB the EPB references. This is necessary because tools can put packets of several sessions on one IDB. An EPB without `epb_packetid`, or on an IDB without `if_name`, has no Interface Context.
5. **No guessing.** If no EPB matches an OmniTap object, readers SHALL report it as unassociated.
6. **Duplicates.** Objects that name the same packet and have byte-for-byte identical COER payloads are one object. Objects that name the same packet but differ are in conflict, and readers SHALL report the conflict without choosing. EPBs with one `epb_packetid` are one packet only if their packet data and timestamps are identical.
7. **One identifier, one observation.** A packet identifier names a packet as one capture session observed it. When several devices capture the same on-air packet, each has its own session, so the observations carry different identifiers although their packet bytes are identical. Readers SHALL NOT compare or merge metadata across sessions.
8. **Technology agreement.** The RAT named by an Interface Context and by the Packet Metadata of its packets SHALL agree; on a mismatch the Packet Metadata governs that packet and the reader reports the mismatch.
9. **Contexts in every file.** A producer SHALL write the Capture Context at the start of every file of a session, the first file included, and the current Interface Context of every interface before the first EPB of that interface in the file. It SHALL NOT restart `recordId` in a later file of the same session.

## Behavior of common tools (`OmniTap` Native vs. `OmniTap-Lua`)
Both stream flavors were tested against the tools users run on capture files: `mergecap`, `editcap`, `reordercap`, `tshark`, and the Wireshark graphical interface (Windows, Wireshark 4.6.9). Each test file held one capture session with one interface, packets with `epb_packetid`, Packet Metadata (as EPB Option `2989` in `OmniTap` Native, and as a preceding Custom Block in `OmniTap-Lua`), a Capture Context, an Interface Context, and a later Supplemental Result. The command-line script `scripts/OmniTap-Survival-Test.py` reproduces the container survival tests.

| Operation | `OmniTap` (Native: EPB Option `2989`) | `OmniTap-Lua` (Custom Block `0x00000BAD`) |
|-----------|---------------------------------------|-------------------------------------------|
| Save As, `editcap` rewrite, `reordercap`, `tshark -w` without a filter | All kept; 1 frame per packet | All kept; 2 frames per packet |
| Add a packet comment, then Save As | All kept | All kept |
| Merge two files chronologically (`mergecap` default) | `PacketMetadata` stays inside its EPB | All kept, but most `PacketMetadata` blocks are separated from their EPB |
| Merge two files that name an interface alike (default mode) | All kept; Interface Context decided per EPB | All kept; Interface Context decided per EPB |
| Merge a file with itself, or `editcap -d` (deduplicate) | Duplicate EPB **and** its `PacketMetadata` option removed together (zero orphans) | Duplicate EPBs removed, but duplicate `PacketMetadata` Custom Blocks stay as orphans |
| Export Specified Packets (selected, marked, or displayed by `frame.packet_id`) | **Kept** for all exported packets (`PacketMetadata` travels inside the EPB); standalone Context/Result Custom Blocks require matching filter | **Lost** for `PacketMetadata`, Contexts, and Results unless the display filter also matches the Custom Blocks |
| `editcap -A/-B` (time window) or `editcap -r` (frame range) | `PacketMetadata` kept for every selected EPB | Frame numbers count Custom Blocks as well as packets; blocks of removed packets can remain unassociated |
| `editcap -c` (split) | `PacketMetadata` stays with every EPB; Context Custom Blocks in first file only | Context Custom Blocks in first file only |

Notes:
- **Why `OmniTap` (Native) is the primary format.** Carrying `PacketMetadata` in EPB Custom Binary Option `2989` eliminates orphan `PacketMetadata` blocks during deduplication (`editcap -d`), keeps 1 packet = 1 Wireshark frame number, preserves per-packet metadata automatically during Wireshark packet exports and `editcap` time/frame slicing, and saves 8 octets per packet (4-octet option header + 4-octet PEN vs. 16-octet Custom Block wrapper).
- **Frame numbers in `OmniTap-Lua`.** In `OmniTap-Lua`, Wireshark gives every Custom Block its own frame number, so frame numbers and `editcap` ranges count OmniTap Custom Blocks as well as packets. Do not use frame numbers to identify a packet.
- **Section Header Block.** Wireshark adds a comment to the Section Header Block of a merged or exported file (the source file names and the operating system). This is the only byte difference from `mergecap` in the tested exports.
- **Duplicate removal.** `editcap -d` compares packet bytes only, over a window of 5 packets by default. For 802.11 captures the Radiotap header differs per receiver, so the copies are not seen as duplicates unless the header is skipped.
- **Lua cannot rewrite Custom Blocks or read EPB Custom Options.** In Wireshark 4.6.9, the Lua API does not expose EPB Option `2989` and the Lua `Dumper` object drops Custom Blocks. Therefore, `scripts/OmniLuazer.py` handles lossless `OmniTap` $\leftrightarrow$ `OmniTap-Lua` conversion and orphan cleanup directly on the `.pcapng` file.

## Producer deployment architectures and the 6-line `OmniTap-Lua` option

Because COER encoding is 100% byte-aligned (~112 RISC instructions per rich packet and ~2 KB of dependency-free C code), an OBU, RSU, AVD, or test instrument can implement OmniTap in two ways:
1. **Monolithic HLOS capture writer:** An application-processor daemon collects the packet bytes, radio measurements, GNSS time/location, and campaign context in user space and writes `CaptureContext`, `InterfaceContext`, `PacketMetadata` (in EPB Option `2989` by default), and later `SupplementalResult` blocks into the `.pcapng` stream.
2. **Split producer architecture (`tcpdump` / `tshark` / `dumpcap`-style capture + late HLOS annotations):**
   - **Stage 1 (Low-level driver or radio capture daemon):** At packet ingress/egress, the driver or capture daemon assigns `epb_packetid = (sessionTag << 32) | recordId` and emits `InterfaceContext` and per-packet `PacketMetadata` containing lower-layer facts immediately available at the radio boundary (per-antenna RSSI/RSRP/RSRQ/SINR, center frequency, bandwidth, TX power, and LTE-V2X / NR-V2X / ITS-G5 / ARIB STD-T109 lower-layer metadata, plus GNSS time/location if shared in memory).
   - **Stage 2 (HLOS upper-layer stack):** Asynchronous upper-layer services (IEEE 1609.2 cryptographic verification, certificate chain checks, upper-layer PDU decoding, and test assertions) emit `OmniTapSupplementalResult` Custom Blocks keyed by `(sessionId, recordId)` without blocking real-time packet capture.

### Reference C99 producer header (`include/omnitap_coer.h`) and the 6-line `OmniTap-Lua` toggle
The repository provides a dependency-free reference C99 header (`include/omnitap_coer.h`) that encodes `COER(OmniTapObject)` payloads (`omnitap_coer_encode_capture_context`, `omnitap_coer_encode_packet_metadata`) without any bit-stream state machine. Because both `OmniTap` (Native) and `OmniTap-Lua` encode the exact same `COER(OmniTapObject)` byte buffer (`meta_buf`, `meta_len`), a producer that wishes to offer direct `OmniTap-Lua` output alongside native `OmniTap` (`omnitap_write_packet` in `include/omnitap_coer.h`) only needs 6 lines of C at the packet-write boundary:

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

Producers are not required to implement this runtime switch on the capture device, because any standard `OmniTap` file can be converted to `OmniTap-Lua` in post-processing with `python scripts/OmniLuazer.py --to-lua input.pcapng output.omnitap-lua.pcapng`.

## Native packet preservation
- **ETSI ITS-G5 (IEEE 802.11p):** Uses `LINKTYPE_IEEE802_11_RADIOTAP` (127). The EPB begins with a standard Radiotap header, which remains authoritative for 802.11 radio and physical-layer information, including channel frequency and the half-rate (10 MHz) and quarter-rate (5 MHz) flags. `21-03-OmniTap-RAT-ETSI-ITSG5.asn` is an extensible hook for information Radiotap cannot carry.
- **LTE-V2X and NR-V2X PC5 (V2X and 3GPP Release 18+ A2X):** Require dedicated LinkType assignments (`00-OmniTap-Registrations.md`). The Layer-2 source and destination IDs in the metadata are 24 bits (three octets, most significant octet first). Both ground V2X and aerial A2X (3GPP TS 23.256) sidelink captures use these modules together with the observer 3D position and vertical-speed fields in `12-OmniTap-Observer.asn`.
- **ITS Connect (ARIB STD-T109):** Requires a dedicated LinkType (`00-OmniTap-Registrations.md`). It is not an 802.11 Radiotap frame. The EPB begins with the 24-octet MAC control field, followed by the LLC PDU (with SNAP). Whether the 4-octet frame check sequence is retained in the EPB is to be settled before the LinkType request is sent. Times inside ITS Connect messages are Japan Standard Time (UTC+9), not the EPB timestamp.
- **Network V2X/A2X (UDP, TCP, MQTT):** Uses `LINKTYPE_ETHERNET` (1) or `LINKTYPE_RAW` (101) and leaves IP packets unchanged.
- **WAVE Service Advertisement (IEEE 1609.30):** Has no dedicated OmniTap object; it is decoded as an IEEE 1609 payload selected by PSID, including over LTE-V2X or NR-V2X.

## Reader (dissector) rationale
OmniTap supports two dissector tiers:
1. **Native compiled C dissector (`asn2wrs`):** Generated directly from the 12 normative ASN.1 modules (`scripts/OmniTap-Validate.py` verifies `asn2wrs -e` compilation on every run). Compiled into Wireshark/`tshark` (or loaded as a native C plugin), it decodes both standard **`OmniTap` (Native)** files (reading `PacketMetadata` from EPB Custom Binary Option `2989` and Contexts/Supplemental Results from Custom Blocks `0x00000BAD`) and **`OmniTap-Lua`** files.
2. **Portable Lua convenience dissector (for older or unmodified Wireshark/TShark builds):** Because stock Wireshark binaries without the compiled OmniTap C dissector do not expose EPB Custom Binary Option `2989` to Lua scripts, the portable Lua dissector reads **`OmniTap-Lua`** streams where `PacketMetadata` has been unpacked into standalone Custom Blocks (`0x00000BAD`). Users with a standard `OmniTap` capture simply run `python scripts/OmniLuazer.py input.pcapng output.omnitap-lua.pcapng` before opening the file in an unmodified Wireshark with the Lua dissector.

To keep `asn2wrs` code generation warning-free, the schema avoids the ASN.1 constructs that `asn2wrs` does not support (see `00-OmniTap-Requirements.md`) and gives every field a name that is unique across the whole protocol, because field names become Wireshark display-filter names.

A reader must not let later context leak into earlier packets. Wireshark can dissect packets out of order, so any state a dissector keeps across packets must not depend on dissection order.

## Adding a future radio access technology
To add a new radio access technology in a minor release:
1. Add the technology behind `...` in `V2XTechnology` (`90-OmniTap-Common.asn`).
2. Add a module `21-NN-OmniTap-RAT-<Name>.asn` with OID `{ 1 3 6 1 4 1 <PEN> omniTap(1) rat(21) <branch>(NN) major-version-1(1) minor-version-0(0) }`.
3. Import its root type into `20-OmniTap-Packet-Metadata.asn` and add a branch behind `...` in `TechnologyMetadata`.
4. Add the file to `omnitap.cmd` and `omnitap.a1sproj`, and pass the validation gate.

