# OmniTap Identifier Registrations — OmniAir Action Plan

Status as of 2026-11-03: no identifier has been requested or assigned yet.

## 1. What OmniAir must obtain

| Identifier                           | Needed for                                          | Authority         | Status        |
|--------------------------------------|-----------------------------------------------------|-------------------|---------------|
| IANA Private Enterprise Number (PEN) | Custom Block and Custom Option 2989 PEN; ASN.1 module OID root; extensions | IANA (FCFS)       | Not requested |
| LinkType: LTE-V2X PC5                | IDB link type for native LTE-V2X / Release 18+ A2X sidelink bytes          | LinkType registry | Not requested |
| LinkType: NR-V2X PC5                 | IDB link type for native NR-V2X / Release 18+ A2X sidelink bytes           | LinkType registry | Not requested |
| LinkType: ITS Connect                | IDB link type for native ITS Connect frames                                | LinkType registry | Not requested |

"LinkType registry" currently means the tcpdump.org Link-Layer Header Types registry (see section 3). The ITS Connect
LinkType is for native ARIB STD-T109 frames. Recheck the submission authority before applying because an IANA transition
is in progress.

Not required:

- ETSI ITS-G5 (IEEE 802.11p): uses the existing `LINKTYPE_IEEE802_11_RADIOTAP` (127).
- Network V2X/A2X (Ethernet/IP/UDP/TCP/MQTT): uses existing link types such as `LINKTYPE_ETHERNET` (1) and `LINKTYPE_RAW` (101).
- pcapng block/option codes: `OmniTap` (Native) uses the standard copyable EPB Custom Binary Option code `2989` (`0x0BAD`, `opt_custom_binary_copy`, IETF OPSAWG pcapng section 3.5.1) and copyable Custom Block code `0x00000BAD` (section 4.8); `OmniTap-Lua` uses copyable Custom Block code `0x00000BAD`. Both are already part of standard pcapng and are disambiguated solely by the owner's 32-bit PEN.
- Module OIDs: these come with the PEN as the arc `1.3.6.1.4.1.<PEN>`. OmniAir then allocates its own sub-arcs.

## 2. IANA Private Enterprise Number

### 2.1 Facts

- Registry: <https://www.iana.org/assignments/enterprise-numbers/>. Governing document: RFC 9371.
- Procedure: First Come First Served. There is no technical review.
- The PEN prefix is `1.3.6.1.4.1`. The values 0 and 4294967295 are reserved.
- On 2026-10-29, a registry search for "OmniAir" returned no entries. Repeat the search before applying. If OmniAir already
  holds a PEN, reuse it; do not request a second one.
- Until assignment, OmniTap development and test artifacts use the documentation PEN 32473 (RFC 5612). It SHALL NOT appear in production files.

### 2.2 Actions

1. **Decide the PEN holder.** Recommended: OmniAir Consortium as the organization. A vendor PEN would tie the profile to
   one member company.
2. **Choose the registered contact.** Use a role mailbox that OmniAir controls, for example a standards or registry
   alias, not an individual's address. A role mailbox survives staff changes; IANA uses it for any later modification.
3. **Apply** with the form at <https://www.iana.org/assignments/enterprise-numbers/assignment/apply/>. Give the legal
   organization name, the contact, and the role mailbox.
4. **Record the assignment** in this file. Then replace 32473 in every module OID, the Custom Block (`0x00000BAD`) and
   EPB Custom Binary Option (`2989` / `0x0BAD`) PEN, `scripts/OmniTap-Validate.py`, `scripts/OmniLuazer.py`,
   `scripts/OmniTap-Generate-Samples.py`, `scripts/OmniTap-Survival-Test.py`, `dissector/omnitap.lua`,
   `dissector/asn2wrs/packet-omnitap-template.c`, `include/omnitap_coer.h`, and the docs.
5. **Create an OmniAir OID sub-arc register** under `1.3.6.1.4.1.<PEN>` and keep it under change control. Proposed:
   `<PEN>.1` = OmniTap, `<PEN>.1.<module>.<version>` = OmniTap ASN.1 modules. Other OmniAir programs then get their own
   arcs (`<PEN>.2`, and so on) without colliding with OmniTap.

## 3. pcapng LinkTypes

### 3.1 Facts

- LinkType values are currently allocated and published by the tcpdump group
  (<https://www.tcpdump.org/linktypes.html>).
- The IETF OPSAWG LinkType work item proposes an IANA "PCAP-related LinkType List" registry with these policies:
  - Values 0–65000 use Expert Review (RFC 8126, Section 4.5).
  - Values 65001–65535 are for Experimental Use and should never leave the entity that uses them.
  - Values 147–162 (`LINKTYPE_RESERVED_01`..`16`, historically `LINKTYPE_USER0`..`15`) are deprecated for new private
    use; new private experiments should use 65001–65535.
  - Initial entries without another reference use `linktype@tcpdump.org` as change controller.
  - Official values are recommended over private values.
- **Current authority** (checked 2026-11-03): the expected IANA PCAP registry URL was not live. Use the tcpdump.org
  process until IANA publishes the registry, and recheck both sites immediately before submitting a request.
- **Proposed expert guidance:** provide a stable specification URL when possible and at minimum a responsible contact.
  If packet data can contain an IPv4 or IPv6 header, specify every octet between the start of the packet data and that
  header.
- **Today's route** (tcpdump.org/linktypes.html, "How To Assign a New Value"):
  1. Prototype with the private `DLT_USERx` values first.
  2. Subscribe to the mailing list that the page links to and send a request. State the standard that describes the
     headers, or link to a permanent public page, or describe the headers in full. If the headers differ from a
     standard in any way (a field added, removed, reordered, or changed in size, endianness or format), describe every
     difference.
  3. Prepare a pull request to libpcap that adds the `DLT_` value (`pcap/dlt.h`), the `LINKTYPE_` value
     (`pcap-common.c`) and the name table entry (`pcap.c`).
  4. Prepare a pull request to the tcpdump web site (`tcpdump-htdocs`) that adds a row to `linktypes.html` and, if no
     other specification is readily available, a new `LINKTYPE_xxxxx.html` page describing the header.
  5. Expect questions and delay. The page warns that after assignment the header structure is set in stone.
  The current registry uses the tcpdump group process. If IANA publishes the proposed registry before submission, use
  the IANA procedure instead.
- **Nothing for V2X exists yet.** The list read on 2026-11-02 has no LinkType for LTE or NR sidelink, ITS-G5 beyond
  the generic 802.11 types (105, 119, 127, 163), ITS Connect, or WAVE. The closest recent precedent is
  `LINKTYPE_DECT_NR_TAP` (304), registered by DSR Corporation: it prepends a small metadata header to a standard
  frame. OmniTap deliberately does not prepend anything, so its LinkTypes describe the bare native frames.

### 3.2 Interim use, before official values

| Use                          | LinkType                                        | Rule                                         |
|------------------------------|-------------------------------------------------|----------------------------------------------|
| Files shared outside the lab | `LINKTYPE_WIRESHARK_UPPER_PDU` (252), with tag  | OmniTap editorial choice; Wireshark-only     |
| IP-only C-V2X interfaces     | `LINKTYPE_RAW` (101)                            | Standard; no OmniTap dissector needed        |
| Lab prototypes only          | 65001–65535 (or 147–162 on older tools)         | Never ship or share files using these values |

"With tag" means each EPB carries the dissector-name tag that `LINKTYPE_WIRESHARK_UPPER_PDU` uses to pick a dissector.

### 3.3 Prerequisites before any LinkType request

An expert reviewer needs a precise, stable byte-level definition of the packet data. OmniTap does not have one yet.
These must be decided first:

1. The exact first byte of EPB packet data for each RAT. For example, LTE/NR PC5: which protocol layer (PDCP SDU,
   PC5 Signalling / non-IP header, or MAC PDU) and which header precedes it. For ITS Connect (ARIB STD-T109): the
   24-octet MAC control field, then LLC/SNAP (protocol ID 0x0001 selects the vehicle/roadside control layer).
2. Whether LTE-V2X and NR-V2X share one LinkType or get one each. Separate values match the per-RAT ASN.1 modules.
3. A reference document that the reviewer can access. Publish the OmniTap packet-format spec openly and cite the 3GPP
   and ARIB standards. The editors hold English translations of both Japanese documents: ARIB STD-T109 version 1.3
   (July 27, 2017) and ITS FORUM RC-010 version 1.1 (September 30, 2017; downloaded from the ITS FORUM web site). Both
   state that the copyright is reserved and that the Japanese original prevails, so OmniTap cites them by clause and
   copies no text. Whether a reviewer can obtain them without charge is NOT yet confirmed; check the ARIB English
   page (the standard names www.arib.or.jp/english) before the first request.
   The 3GPP specifications are public.
4. Sample capture files for each requested value.

### 3.4 Actions

1. **Write a packet-data format page** for each requested LinkType. Use the same structure as the existing pages on
   tcpdump.org: a byte-layout diagram, field descriptions, and normative references.
2. **Prepare the request**, one per LinkType:
   - proposed name, e.g. `LINKTYPE_LTE_V2X_PC5`, `LINKTYPE_NR_V2X_PC5`, `LINKTYPE_ARIB_T109`;
   - short description;
   - change controller: OmniAir, using the role mailbox from 2.2;
   - reference: the public format page from step 1;
   - sample captures.
3. **Submit early**, as soon as the format pages are stable. This does not need to wait for the full OmniTap release.
4. **After assignment**, open a Wireshark merge request (<https://gitlab.com/wireshark/wireshark>). It adds the LinkType
   mapping and dissector registration, so files open without any user configuration.
5. **Record each assigned value** in this file, the README, and the dissectors. Retire the interim
   `LINKTYPE_WIRESHARK_UPPER_PDU` path.

## 4. Owners and tracking

| Action                                  | Owner (OmniAir) | Depends on               | Done |
|-----------------------------------------|-----------------|--------------------------|------|
| Decide PEN holder and role mailbox      | TBD             | —                        | No   |
| Submit IANA PEN application             | TBD             | PEN holder decision      | No   |
| Create OID sub-arc register             | TBD             | PEN assigned             | No   |
| Define per-RAT EPB packet-data layout   | OmniTap editors | Open design decision     | No   |
| Publish packet-data format pages        | OmniTap editors | EPB layout               | No   |
| Submit LinkType requests                | TBD             | Format pages, samples    | No   |
| Wireshark upstream merge request        | OmniTap editors | LinkTypes and PEN        | No   |

