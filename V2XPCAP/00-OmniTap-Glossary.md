# OmniTap Glossary

This glossary defines every term, abbreviation, and identifier convention used in the OmniTap documents and ASN.1 modules, with references. Definitions are written in the editors' own words. They do not reproduce standards text. Where a clause number is given, read the clause for the authoritative statement.

## How to read this glossary
- **Columns.** *Term*, *Meaning*, *Reference*.
- **† (dagger).** The cited text was read in the editors' local copies of the documents or fetched during development. A reference without † is cited from the editors' knowledge and SHALL be checked before public release. "(to confirm)" marks an item that is known to need checking.
- **Versions.** References name the authoritative document or registry. An edition is included when technical content or lifecycle status depends on it.
- **Files.** A reference such as `90-` means the ASN.1 module whose filename starts with `90-`.

## 1. Document conventions
| Term | Meaning | Reference |
|------|---------|-----------|
| SHALL, SHALL NOT | A requirement that a conforming implementation has to meet. OmniTap uses SHALL as its strongest requirement word. | BCP 14 (RFC 2119, RFC 8174)† |
| SHOULD, SHOULD NOT | A recommendation. There may be a valid reason to differ, but the effect must be understood first. | BCP 14† |
| MAY | Optional behavior. | BCP 14† |
| Normative, informative | Normative text sets a requirement. Informative text only explains. In ASN.1 comments, a comment beginning "Normative:" sets a requirement. | |
| Octet | Eight bits. The schema says octet, not byte. | |
| Most significant octet first (big-endian, network byte order) | A multi-octet number is written with its highest-order octet first. | RFC 9562 §4† |
| MSB, LSB | Most significant and least significant bits or octets of a value. "The 16 MSB" means the highest 16 bits. | |
| ID | Identifier. | |
| TBD | To be determined. | |
| kB, MB, GB | Decimal units: 1 kB is 1,000 bytes, 1 MB is 1,000,000 bytes, 1 GB is 1,000,000,000 bytes. | `00-OmniTap-Requirements.md` |
| NN | Placeholder for a two-digit number in file-name patterns such as `NN-OmniTap-<Name>.asn`. | `scripts/OmniTap-Validate.py` |
| README | The file `00-OmniTap-README.md`. | |

## 2. OmniTap terms
| Term | Meaning | Reference |
|------|---------|-----------|
| OmniTap (`OmniTap` Native) | The extensible, technology-neutral V2X capture metadata profile defined by this repository: ASN.1 types encoded as COER (ITU-T X.696), with per-packet `PacketMetadata` carried inside each EPB as Custom Binary Option `2989` (`0x0BAD`) and `CaptureContext`, `InterfaceContext`, and `SupplementalResult` carried in standalone copyable Custom Blocks (`0x00000BAD`). | README |
| `OmniTap-Lua` | The lossless Lua-compatibility stream flavor for older or unmodified stock Wireshark/TShark installations using only the portable Lua dissector (without the compiled `asn2wrs` C dissector), in which `PacketMetadata` is unpacked into a standalone copyable Custom Block (`0x00000BAD`) preceding its EPB. | README |
| `OmniLuazer` (`scripts/OmniLuazer.py`) | The Python tool that losslessly converts between `OmniTap` (Native) and `OmniTap-Lua` (`--to-lua`, `--to-native`) and cleans orphan Custom Blocks (`--clean-orphans`). | README |
| OmniTap object (`OmniTapObject`) | The unit carried in one Custom Block or EPB Custom Binary Option `2989`: a profile version followed by exactly one body. | `00-OmniTap-Objects.asn` |
| Profile version | Two integers, major and minor, at the start of every object. In COER/OER they are always in the first four octets of the payload (`0x00` `OmniTapObject` preamble, `0x00` `OmniTapProfileVersion` preamble, 1-octet `major`, 1-octet `minor`), followed by the 1-octet body `CHOICE` tag. A reader checks the major version before decoding the body. | `00-OmniTap-Objects.asn`; README |
| Body | The part of an object that differs by kind: capture context, interface context, packet metadata, or supplemental result. | `00-OmniTap-Objects.asn` |
| Capture Context | An object describing a whole capture session: session identity and test-campaign details. | `00-OmniTap-Objects.asn` |
| Interface Context | An object describing one capture interface, such as its time context. It is matched for each EPB: by the `sessionTag` in the EPB's `epb_packetid` and the `if_name` of the EPB's Interface Description Block. | `10-` |
| Packet Metadata | An object describing one captured packet: its `recordId`, payload description, and optional observer, time, and technology data. | `20-` |
| Technology metadata | The part of Packet Metadata that is specific to one radio access technology. It is an ASN.1 CHOICE with one branch per technology. | `20-`; `21-NN` modules |
| Supplemental Result | An object written later that carries analysis of an earlier packet. It is matched to the packet by `sessionId` and `recordId`. | `30-` |
| Optional extensions (`optionalExtensions`) | A field, present in every object that has extension space, holding up to two regional and up to two PEN-owned extension values. PEN-owned values may describe manufacturer-private capabilities, proprietary diagnostics, calibration data, or tool-specific annotations. Each extension carries an owner identity, a type, and opaque octets that base readers do not interpret. | `40-` |
| `opaqueValue` | The octets inside an extension container. Their meaning belongs to the extension owner. | `40-` |
| Producer | The program or device that writes an OmniTap file or a result. A Supplemental Result names its producer by PEN, product name, and optional software version. | `30-` |
| Reader | A program that reads OmniTap data. A dissector is a reader. | `00-OmniTap-Architecture.md` |
| Observer | The capture device, with its location, antenna, and radio, at the time of capture. | `12-` |
| Observer location | One location of the capture platform at the packet's timestamp. It is the same whether the packet was received or transmitted. | `12-` |
| Radio observation | One structure of radio measurements and configuration for a packet. Each field says whether it applies to reception, transmission, or both. The direction itself comes only from the EPB's `epb_flags`. | `12-` |
| Capture session | One continuous capture run, identified by a `CaptureSessionId`. It can span several pcapng sections and files. | `90-` |
| `CaptureSessionId` | A 128-bit session identity assigned by the producer. A UUIDv7 is recommended. | `90-`; RFC 9562† |
| `sessionTag` | The last four octets of the `CaptureSessionId`, read as an unsigned big-endian number. It is the high 32 bits of `epb_packetid`. | `90-` |
| `recordId` | The producer's packet counter within a session. It is the low 32 bits of `epb_packetid`. | `90-` |
| Association | Linking an OmniTap object to the packet it describes by explicit fields, never by position in the file. | `00-OmniTap-Architecture.md` |
| Unassociated | The state of an OmniTap object for which no packet, or more than one packet, matches. Readers report it and do not guess. | `00-OmniTap-Requirements.md` |
| Orphan block | An OmniTap Custom Block whose packet is no longer in the file, for example because `editcap -d` removed the duplicate packet but not its blocks. An orphan is unassociated. | README, "Working with OmniTap files" |
| `resultSequence` | A number from 0 to 65535 within one producer. Of two results from the same producer, the higher number supersedes the lower. | `30-` |
| Absent and `unavailable` | An absent OPTIONAL value makes no assertion. A value of `unavailable` means the check was attempted but could not run or complete. | `30-`; `00-OmniTap-Requirements.md` |
| Native packet bytes | The packet data in the Enhanced Packet Block, exactly as captured. OmniTap never changes them. | README |
| Placeholder identifier | A value used only during development and in test data, such as the documentation PEN 32473. It SHALL NOT appear in production files. | `00-OmniTap-Registrations.md` |
| Release gate | The checks that must pass before public release: two independent ASN.1 compilers and the `asn2wrs` generator, each with no errors or warnings. | `00-OmniTap-Requirements.md` |
| Repository validation (`00-OmniTap-Validate.py`) | The script that checks the repository's own rules and runs two of the gate steps locally. It supplements the gate. | README |

## 3. pcapng terms
| Term | Meaning | Reference |
|------|---------|-----------|
| pcapng | The PCAP Next Generation capture-file format: a file made of typed blocks. The actively maintained IETF OPSAWG specification has not yet been published as an RFC. | IETF OPSAWG pcapng specification §3.1† |
| PCAP | The older packet-capture file format and the LinkType naming scheme taken from it. | tcpdump.org Link-Layer Header Types registry† |
| Block | The basic unit of a pcapng file: a type, a length, a body, and optionally options. | IETF OPSAWG pcapng specification §3.1† |
| Section | A run of blocks that starts with a Section Header Block. Interfaces are numbered within a section. | IETF OPSAWG pcapng specification §3.4, §4.1† |
| SHB (Section Header Block) | The block that starts a section. | IETF OPSAWG pcapng specification §4.1† |
| IDB (Interface Description Block) | The block that describes one capture interface: its LinkType, name, and timestamp resolution. | IETF OPSAWG pcapng specification §4.2† |
| EPB (Enhanced Packet Block) | The block that holds one captured packet with its timestamp and interface number. | IETF OPSAWG pcapng specification §4.3† |
| Custom Block | A block owned by an organization identified by a PEN. Type `0x00000BAD` may be copied to a new file. Type `0x40000BAD` should not be. OmniTap uses the copyable type. | IETF OPSAWG pcapng specification §4.8† |
| Option | A typed field in the list at the end of a block. | IETF OPSAWG pcapng specification §3.5† |
| Custom Option, Custom Binary Option | An organization-owned option attached to a standard block. OmniTap does not use them, because the tested Lua interface did not expose them. | IETF OPSAWG pcapng specification §3.5.1†; README |
| Interface ID | The number of an IDB within its section. It changes when files are merged, so OmniTap never relies on it. | IETF OPSAWG pcapng specification §4.2† |
| `if_name` | An IDB option holding the interface name. With the session tag from `epb_packetid` it selects the Interface Context for an EPB. | IETF OPSAWG pcapng specification §4.2† |
| `if_tsresol` | An IDB option giving the timestamp resolution. OmniTap allows the values 3 (milliseconds), 6 (microseconds, the pcapng default when omitted), and 9 (nanoseconds). | IETF OPSAWG pcapng specification §4.2† |
| `epb_packetid` | An EPB option holding a 64-bit unsigned packet identifier. It stays with the packet when files are merged or filtered. Wireshark shows it as `frame.packet_id`. | IETF OPSAWG pcapng specification §4.3†; Wireshark `packet-frame.c`† |
| LinkType | The number in an IDB that says what format the packet data has. | tcpdump.org Link-Layer Header Types registry† |
| `LINKTYPE_ETHERNET` (1), `LINKTYPE_RAW` (101), `LINKTYPE_IEEE802_11_RADIOTAP` (127), `LINKTYPE_WIRESHARK_UPPER_PDU` (252) | Existing LinkTypes OmniTap uses or names. Names and values come from the active tcpdump.org registry. | tcpdump.org Link-Layer Header Types registry† |
| Experimental LinkType range (65001 to 65535) | Values proposed for use inside one organization only. OmniTap test files using them SHALL NOT be shared. | IETF OPSAWG LinkType work item† |
| Wireshark Export Specified Packets | A Wireshark function that saves chosen packets to a new file. | Wireshark User's Guide |
| `mergecap`, `editcap` | Wireshark command-line tools that combine capture files and edit them (trim, split, remove duplicates). | Wireshark manual pages |

## 4. ASN.1 and encoding terms
| Term | Meaning | Reference |
|------|---------|-----------|
| ASN.1 | Abstract Syntax Notation One: a language for describing data structures. | ITU-T X.680 |
| Module | A named ASN.1 unit. Each `.asn` file is one module. | ITU-T X.680 |
| OID (object identifier) | A path of numbers that uniquely names something. OmniTap module OIDs sit under the PEN arc `1.3.6.1.4.1.<PEN>`. | ITU-T X.660; RFC 9371† |
| COER, OER | Canonical Octet Encoding Rules and Basic Octet Encoding Rules: compact, byte-aligned ASN.1 encodings in which constrained integers map to 1-, 2-, 4-, or 8-octet big-endian integers. OmniTap mandates COER for producers; every COER encoding is also valid Basic OER. | ITU-T X.696 |
| UPER | Unaligned Packed Encoding Rules: a bit-packed encoding with no byte alignment between fields. Requirements compares COER with UPER and TLV. | ITU-T X.691 |
| PER, BER | The families of encoding rules. PER is the bit-packed family that contains UPER. BER is the older tag-length-value family. | ITU-T X.691; X.690 |
| TLV | Type-length-value: a generic encoding that writes each field's type and length. Requirements compares it with COER and UPER. | `00-OmniTap-Requirements.md` |
| Extension marker (`...`) | Marks a type as extensible. A later version may add content that an older reader skips. | ITU-T X.680 |
| `AUTOMATIC TAGS` | A module option that lets the compiler assign tags. Every OmniTap module uses it. | ITU-T X.680 |
| `SEQUENCE`, `SEQUENCE OF` | An ordered group of named fields, and a list of one type. | ITU-T X.680 |
| `CHOICE` | A type that holds exactly one of several alternatives. | ITU-T X.680 |
| `ENUMERATED` | A type with named integer values. | ITU-T X.680 |
| `OPTIONAL` | A field that may be absent. In OmniTap, absent means no assertion. | ITU-T X.680; `00-OmniTap-Requirements.md` |
| `OCTET STRING`, `SIZE` | A string of octets, and a limit on its length. | ITU-T X.680 |
| `INTEGER (a..b)` | An integer limited to a range. COER/OER uses the range to choose a 1-, 2-, 4-, or 8-octet integer width and validates the bounds. | ITU-T X.680, X.696 |
| `UTF8String` | A text type holding Unicode in UTF-8. | ITU-T X.680; RFC 3629 |
| `IMPORTS`, `EXPORTS` | The module statements that bring in and publish type names. Every OmniTap module exports all. | ITU-T X.680 |
| ASN.1 keywords (`BEGIN`, `END`, `DEFINITIONS`, `FROM`, `ALL`, `BOOLEAN`, `TRUE`, `FALSE`, `INTEGER`, `MAX`, `OF`, `STRING`) | Reserved words of the notation. | ITU-T X.680 |
| `COMPONENTS OF` | An ASN.1 directive that copies the fields of another SEQUENCE into this one. OmniTap does not use it, because `asn2wrs` does not support it. | `00-OmniTap-Requirements.md`; Wireshark Developer's Guide §17.8† |
| Parameterized type | A type definition that takes parameters. Not used in OmniTap. | Wireshark Developer's Guide §17.8† |
| Tagged assignment (`APPLICATION`, `IMPLICIT`) | A type definition that sets an explicit tag. Not used in OmniTap. | Wireshark Developer's Guide §17.8† |
| Information object class, open type, `ANY` | ASN.1 ways to leave a field's type to be decided by another field. Not used by OmniTap. | `00-OmniTap-Requirements.md` |
| ASN.1 compiler | A tool that checks ASN.1 modules and generates code from them. The release gate needs two independent ones. | `00-OmniTap-Requirements.md` |
| `asn2wrs` | The Wireshark tool that generates dissector source code from ASN.1. | Wireshark Developer's Guide, chapter 17† |

## 5. Registries and identifiers
| Term | Meaning | Reference |
|------|---------|-----------|
| IANA | The Internet Assigned Numbers Authority: the keeper of the PEN registry and many other registries. | RFC 9371† |
| PEN (Private Enterprise Number) | A number that IANA assigns to an organization. OmniTap uses it to own Custom Blocks and as the root of its OIDs. | RFC 9371† |
| Documentation PEN 32473 | A PEN reserved for examples. OmniTap development and test artifacts use it as a placeholder until a production PEN is assigned. | RFC 5612†; RFC 9371 §3† |
| RFC | Request for Comments: the IETF document series. | |
| BCP | Best Current Practice: an IETF document class. BCP 14 defines the requirement keywords. | |
| FCFS (First Come First Served) | A registration policy in which IANA records requests in order, without technical review. The PEN registry uses it. | RFC 8126 §4.4†; RFC 9371 §2† |
| Expert Review | A registration policy in which a designated expert decides. The proposed IANA LinkType registry uses it for values 0 to 65000. | RFC 8126 §4.5†; IETF OPSAWG LinkType work item† |
| Change controller | The party that may ask to change a registry entry. | tcpdump.org Link-Layer Header Types registry† |
| tcpdump group | The group that has historically allocated LinkType values. | tcpdump.org/linktypes.html |
| UUID | Universally Unique Identifier: a 128-bit identifier. | RFC 9562† |
| UUIDv7 | A UUID whose leading octets are a timestamp and whose trailing octets are random. OmniTap recommends it for `CaptureSessionId` and uses the trailing octets for `sessionTag`. | RFC 9562† |

## 6. Radio and V2X/A2X terms
| Term | Meaning | Reference |
|------|---------|-----------|
| V2X | Vehicle-to-everything: communication between a vehicle and other vehicles, roadside units, pedestrians, or networks. | 3GPP TS 23.285 |
| A2X | Aircraft-to-everything: communication between an uncrewed aerial vehicle (UAV), urban air mobility (UAM) aircraft, ground station, or other airspace/ground entity over 3GPP LTE or NR PC5 sidelink or IP networks. | 3GPP TS 23.256 |
| RAT (radio access technology) | One way of using the radio, such as LTE-V2X or ITS-G5. Each has an OmniTap module in the `21-NN` series. | `20-`; `21-NN` modules |
| ITS | Intelligent transportation systems. | IEEE Std 1609.2-2025† |
| PHY | The physical layer of a radio protocol. | |
| MAC | Medium access control: the protocol layer above the PHY that frames data and controls access to the channel. | 3GPP TS 36.321†; IEEE 802.11 |
| RF | Radio frequency. | |
| LLC (Logical Link Control) | The IEEE 802.2 layer that identifies the protocol carried in a frame. | IEEE 802.2 |
| SNAP (Subnetwork Access Protocol) | An LLC extension that carries a protocol identifier. ITS Connect frames use it. | IEEE 802.2 |
| PDU, SDU | Protocol data unit: a message at one protocol layer. Service data unit: the payload handed to that layer from above. | 3GPP TS 36.321† |
| Layer-2 ID | The data-link address of a sender or receiver. For LTE-V2X and NR-V2X it is always 24 bits. | 3GPP TS 36.321 §6.2.4† |
| Payload kind | Whether the packet data starts with an IP packet or belongs to a non-IP protocol family. | `90-` |
| Non-IP family ID | The 3GPP code naming a non-IP protocol family. OmniTap mirrors the values assigned in TS 24.386. | 3GPP TS 24.386; `90-` |
| ISO 29281-1 | The ISO standard for non-IP networking in intelligent transport systems. Named as a non-IP family (to confirm title). | `90-` |
| DSMP | The name of a Chinese non-IP V2X family listed in the non-IP family code. Expansion to be confirmed. | `90-`; 3GPP TS 24.386 |

## 7. 3GPP terms (LTE-V2X and NR-V2X)
| Term | Meaning | Reference |
|------|---------|-----------|
| 3GPP | The 3rd Generation Partnership Project: the body that writes the LTE and NR specifications. | |
| TS | Technical Specification: a 3GPP document. | |
| LTE | Long Term Evolution: the fourth-generation cellular system, also called E-UTRA. | 3GPP TS 36.321 |
| NR | New Radio: the fifth-generation cellular radio. | 3GPP TS 38.321 |
| LTE-V2X | V2X over the LTE sidelink. | 3GPP TS 23.285; TS 36.321† |
| NR-V2X | V2X over the NR sidelink. | 3GPP TS 23.287; TS 38.321 |
| UE (user equipment) | A device that uses the cellular radio. | 3GPP TS 36.321 |
| Sidelink | A direct link between devices that does not pass through a network node. | 3GPP TS 36.321, clause 3† |
| PC5 | The interface name for the sidelink between two UEs. | 3GPP TS 36.321, clause 3† |
| ProSe | Proximity-based services: the 3GPP feature on which the LTE sidelink was first built. | 3GPP TS 23.303; TS 36.321† |
| SCI (sidelink control information) | The control message that carries scheduling information for a sidelink transmission. | 3GPP TS 36.321, clause 3†; LTE format 1 in TS 36.212 §5.4.3.1.2†; NR formats in TS 38.212 |
| MCS (modulation and coding scheme) | An index that selects the modulation and coding rate. | 3GPP TS 36.212 §5.4.3.1.2† |
| PPPP | ProSe Per-Packet Priority: the priority of an LTE sidelink packet. | 3GPP TS 36.321, clause 3†; TS 23.285 |
| HARQ | Hybrid automatic repeat request: the retransmission method that combines the original and repeated transmissions. | 3GPP TS 36.321, clause 3† |
| Transport block | The unit of data that the MAC layer hands to the PHY for one transmission. | 3GPP TS 36.321† |
| Subframe, SFN | A 1 ms time unit in LTE. The system frame number counts frames from 0 to 1023. | 3GPP TS 36.211 (to confirm) |
| RRC (radio resource control) | The control protocol that configures the radio. | 3GPP TS 36.331 (LTE), TS 38.331 (NR) (to confirm) |
| RRC configuration snapshot | A native RRC configuration, carried unchanged as octets, so the configuration in force can be examined later. | `21-01-`; `21-02-` |
| PDCP | Packet Data Convergence Protocol: a layer above RLC that handles headers and ciphering. | 3GPP TS 36.323, TS 38.323 (to confirm) |
| RLC | Radio Link Control: a layer between PDCP and MAC that segments and reassembles data. | 3GPP TS 36.322, TS 38.322 (to confirm) |

## 8. ETSI ITS-G5 terms
| Term | Meaning | Reference |
|------|---------|-----------|
| ETSI | The European Telecommunications Standards Institute. | |
| ITS-G5 | The European ITS radio technology in the 5.9 GHz band, based on IEEE 802.11p. | ETSI EN 302 663 |
| EN 302 663 | The ETSI specification of the ITS-G5 access layer (to confirm title). | ETSI EN 302 663 |
| IEEE 802.11p | The amendment that adapted IEEE 802.11 for vehicular use. It is now part of the base IEEE 802.11 standard. | IEEE 802.11 |
| OCB (outside the context of a BSS) | An 802.11 mode in which devices exchange frames without joining a network. ITS-G5 uses it. | IEEE 802.11; IEEE Std 1609.2-2025† |
| BSS (basic service set) | An 802.11 network of one access point and its stations. | IEEE 802.11 |
| Radiotap | A header placed before captured 802.11 frames to carry radio and PHY information. Its fields are defined at radiotap.org. Its Channel field gives the frequency, and flags mark half-rate (10 MHz) and quarter-rate (5 MHz) channels, so it identifies an ITS-G5 channel. | radiotap.org†; Wireshark field list† |
| CAM | Cooperative Awareness Message: the ETSI message by which vehicles announce their presence and state. Its PSID is 36. | ETSI EN 302 637-2; ETSI TS 103 759† |
| DENM | Decentralized Environmental Notification Message: the ETSI message that reports a road hazard or event. Its PSID is 37. | ETSI EN 302 637-3; ETSI TS 103 759† |

## 9. ITS Connect terms
| Term | Meaning | Reference |
|------|---------|-----------|
| ITS Connect | The Japanese V2X system in the 760 MHz band. It is built on ARIB STD-T109 and the ITS FORUM RC-010 extended layer. | ARIB STD-T109; ITS FORUM RC-010 |
| ARIB | The Association of Radio Industries and Businesses (Japan). | |
| ARIB STD-T109 | The ARIB standard for the 700 MHz band ITS radio. It uses a single 760 MHz channel. OmniTap names its module and enumeration value `aribT109`. The English translations of version 1.1 (December 18, 2012) and version 1.3 (July 27, 2017) were read. The MAC protocol data unit is a 24-octet MAC control field, an LLC protocol data unit, and a 4-octet frame check sequence (clause 4.3.2, Figure 4-2). The LLC protocol identifier (clause 4.3.5.6.3) has 5 octets; its last two octets are 0x0001 for the inter-vehicle and roadside-to-vehicle communication control layer, and 0x0002 to 0xFFFF are reserved. | ARIB STD-T109†, clauses 4.3.2 and 4.3.5.6.3 |
| ITS FORUM RC-010 | The ITS Info-communications Forum guideline titled "700MHz Band Intelligent Transport Systems - Extended Functions Guideline". ITS Connect uses its extended layer. The English translation of version 1.1 (September 30, 2017) was read. | ITS Connect TD-001, reference list†; ITS FORUM web site |
| ITS Connect TD-001 | The ITS Connect specification of the inter-vehicle communication messages. Version 1.0 is dated September 30, 2015. | ITS Connect TD-001† |
| ITS Connect TD-002 | The ITS Connect communication parameter specification. TD-001 cites it; the editors have not read it. | ITS Connect TD-001, reference list† |
| MAC control field | A 24-octet field at the start of an ARIB STD-T109 frame, before the LLC and SNAP headers. | ARIB STD-T109 |
| JST (Japan Standard Time) | UTC plus nine hours. ITS Connect message times use it. They are not the EPB timestamp, which is always UTC. | `21-04-` |

## 10. IEEE 1609 and security terms
| Term | Meaning | Reference |
|------|---------|-----------|
| IEEE 1609.2 | The standard for security services for WAVE messages: signing, verification, and certificates. | IEEE Std 1609.2-2025† |
| WAVE | Wireless Access in Vehicular Environments: the IEEE 1609 family of standards. | IEEE Std 1609.2-2025† |
| WSMP | WAVE Short Message Protocol: a compact network-layer protocol for short messages. | IEEE Std 1609.3† |
| WSA | WAVE Service Advertisement: a message that advertises services. OmniTap has no WSA-specific object. IEEE 1609.30 specifies WSA. | IEEE Std 1609.30 |
| PSID | Provider Service Identifier: an integer that names an application and the permissions that apply to it. Allocations are in IEEE 1609.12. Examples: BSM 32, CAM 36, DENM 37. | IEEE Std 1609.2-2025†; IEEE 1609.12 |
| SPDU | Security services protocol data unit: a message signed or encrypted under IEEE 1609.2. | IEEE Std 1609.2-2025† |
| SSP | Service Specific Permissions: application-specific permissions carried in a certificate. | IEEE Std 1609.2-2025† |
| SDEE | Secure data exchange entity: the application that sends or receives secured messages. | IEEE Std 1609.2-2025† |
| SCMS | Security Credential Management System: the system that issues and manages V2X certificates. | IEEE Std 1609.2-2025† |
| CRL | Certificate revocation list: a list of revoked certificates. | IEEE Std 1609.2-2025† |
| `HashedId8` | The 8-octet identifier of a certificate, taken from a hash. OmniTap restates it locally. | IEEE 1609.2 ASN.1 base types† |
| Verification result | The outcome of checking a secured message. OmniTap numbers the 41 results in the order specified by IEEE Std 1609.2-2025 because its ASN.1 does not assign numeric values to them. | IEEE Std 1609.2-2025†; `30-` |

## 11. Misbehavior terms
| Term | Meaning | Reference |
|------|---------|-----------|
| Misbehavior | Behavior by a V2X device that breaks the rules of the system, whether from a fault or from an attack. | SAE J3287† |
| MBD (misbehavior detection) | Checks, run locally on a device, that look for misbehavior. | SAE J3287 §4.2.1† |
| Misbehavior report | A report of observed misbehavior, sent to a misbehavior authority. | SAE J3287 §5† |
| SAE | SAE International. | |
| SAE J3287 | The SAE standard for V2X misbehavior reporting. OmniTap restates its identifiers locally. | SAE J3287† |
| SAE J2735 | The SAE message set dictionary, which defines the BSM. | SAE J2735 |
| BSM | Basic Safety Message: the SAE J2735 message that vehicles broadcast about their state. Its PSID is 32. | SAE J2735; ETSI TS 103 759† |
| SAE J3161 | The SAE document series whose channel-quality and vehicle-density values OmniTap records. Title to be confirmed. | SAE J3161 (to confirm) |
| ETSI TS 103 759 | The ETSI specification of the ITS misbehaviour reporting service. OmniTap cites version 2.1.1 or later. | ETSI TS 103 759† |
| ETSI TS 103 097 | The ETSI specification of the security headers and certificate formats. | ETSI TS 103 097 |
| Target ID, observation ID | The two numbers that identify what a misbehavior report is about and what was observed. | `30-`; SAE J3287† |

## 12. Time and position terms
| Term | Meaning | Reference |
|------|---------|-----------|
| UTC | Coordinated Universal Time. | IEEE Std 1609.2-2025† |
| POSIX UTC | A count of seconds since 1970-01-01 UTC that ignores leap seconds. EPB timestamps use it. | IEEE Std 1003.1 |
| TAI | International Atomic Time: a continuous time scale that IEEE 1609.2 uses. | IEEE Std 1609.2-2025† |
| Timestamp resolution (`if_tsresol` = 3, 6, or 9) | The OmniTap requirement that EPB timestamps use millisecond (3), microsecond (6, the pcapng default when omitted), or nanosecond (9) POSIX UTC resolution. | `00-OmniTap-Requirements.md` |
| Duration and `Us` suffix | A field name ending in `Us` holds a duration in microseconds, not a timestamp. The largest value of `ElapsedTimeUs`, 4294967295 (about 71.6 minutes), means that long or longer. | `11-`; `90-`; README |
| GNSS | Global navigation satellite system. | |
| GPS | The United States GNSS. OmniTap records the UTC-to-GPS offset in whole seconds. | `11-` |
| 1PPS | A one-pulse-per-second electrical timing signal from a GNSS receiver. | `11-` |
| NTP | Network Time Protocol: time synchronization over IP. | RFC 5905 |
| PTP | Precision Time Protocol: time synchronization defined by IEEE 1588. | IEEE 1588 |
| Clock quality | Whether and how well the capture clock is disciplined. | `11-` |
| Coordinate reference system | The model in which a position is expressed: a geodetic datum, possibly with a deliberate warp of the coordinates. A warp need not be a two-dimensional shift. OmniTap names `wgs84`, `gcj02` and `other`, and the list can grow. | `12-` |
| WGS 84 | World Geodetic System 1984: a geodetic datum for latitude, longitude, and altitude. IEEE 1609.2 uses it. ITS Connect messages use it or an equivalent. | `12-`; IEEE 1609.2 base types†; ITS Connect TD-001 §6.3.1† |
| GCJ-02 | A coordinate system that adds a deliberate offset to the latitude and longitude of a WGS 84 position. It does not shift altitude. | `12-` |
| Geodetic datum | The reference ellipsoid and origin from which positions are measured. A coordinate reference system may be built on one. | `12-` |
| `E7` suffix | A coordinate in degrees multiplied by 10^7. | `12-` |

## 13. Radio measurement terms
| Term | Meaning | Reference |
|------|---------|-----------|
| dB, dBm | Decibels, and decibels relative to one milliwatt. | |
| `X10` suffix | A value multiplied by 10, so that one decimal place is kept in an integer. | `12-` |
| RSSI | Received signal strength indicator. | `12-` |
| RSRP | Reference signal received power: an LTE and NR power measurement. | 3GPP TS 36.214, TS 38.215 (to confirm) |
| RSRQ | Reference signal received quality: an LTE and NR quality measurement. | 3GPP TS 36.214, TS 38.215 (to confirm) |
| SINR | Signal-to-interference-plus-noise ratio. | 3GPP TS 38.215 (to confirm) |
| Channel load | A producer-defined measure of how busy the channel is near a packet. | `12-` |

## 14. Network and transport terms
| Term | Meaning | Reference |
|------|---------|-----------|
| IP | Internet Protocol. | RFC 791; RFC 8200 |
| Ethernet | The IEEE 802.3 local-area network format. | IEEE 802.3 |
| UDP, TCP | User Datagram Protocol, and Transmission Control Protocol. | RFC 768; RFC 9293 |
| MQTT | Message Queuing Telemetry Transport: a publish-subscribe messaging protocol. | OASIS MQTT |
| TLS | Transport Layer Security. | RFC 8446 |
| HTTPS | HTTP carried over TLS. SCMS exchanges use it. | RFC 9110 |
| Network V2X | V2X messages carried over ordinary IP networks and left as IP traffic in the EPB. | `00-OmniTap-Architecture.md` |

## 15. Tools
| Term | Meaning | Reference |
|------|---------|-----------|
| Wireshark | The packet analyzer for which OmniTap's reference dissector is written. | wireshark.org |
| Dissector | The code that decodes a protocol and shows its fields. | Wireshark Developer's Guide† |
| Lua | The scripting language Wireshark supports for portable dissectors. | Wireshark Developer's Guide† |
| `tshark` | The command-line version of Wireshark. | Wireshark manual pages |
