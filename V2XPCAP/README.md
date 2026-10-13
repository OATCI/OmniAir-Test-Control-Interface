# V2X Capture Metadata Profile — UPER / Per-EPB Metadata

## Philosophy

This is an open **pcapng profile**, not a replacement capture-file
format. It preserves normal pcapng blocks and native packet bytes. One
logical V2X packet is represented by one Enhanced Packet Block (EPB).
The profile does not modify pcapng, reinterpret the EPB block type, or
insert a universal V2X header in front of DSRC Radiotap.

The compact profile model is:

- `V2XCaptureMetadata` is one optional per-EPB metadata object.
- **UPER** is the mandatory structured encoding for all profile-defined
  ASN.1 objects.
- The standard **EPB timestamp is the only capture timestamp**.
- The duplicate ASN.1 receive/transmit timestamp is removed.
- Dynamic observer location, speed, heading, and radio observations
  remain optional fields in that EPB's UPER object.
- Security, relevance, consistency, Misbehavior Detection, and
  application annotations
  also remain optional fields in that EPB's UPER object.
- The profile uses **no correlated observer-state block** and **no
  correlated analysis block**.

This deliberately trades some repeated optional per-packet data for a
self-contained record: extracting, merging, or filtering an EPB does
not require reconstructing state from another profile-defined block.

## pcapng carriage

### IDB-level interface context

Each V2X interface uses an ordinary pcapng Interface Description Block
(IDB) and its normal LinkType. The profile may place
`UPER(V2XInterfaceMetadata)` in an OmniAir-defined Custom Binary Option
on that IDB. It describes stable interface and time interpretation
context; it is **not** a correlated packet-state record.

The IDB profile metadata declares the epoch and timestamp reference point
for all EPBs that name the IDB. A conforming V2X interface sets the
ordinary pcapng `if_tsresol` option to one-microsecond resolution.

The standard EPB timestamp therefore means:

- **RX:** capture time at the IDB-declared receive reference point.
- **TX:** capture time at the IDB-declared transmit reference point.

A producer must not label host submission as OTA transmit start. If it
knows only submission time, it declares `submittedToRadio`.

### EPB metadata

The base option is associated with one ordinary EPB. The EPB block type
remains `0x00000006`; native packet bytes remain unchanged.

```text
EPB Custom Binary Option value
    OmniAir IANA PEN (32 bits)
    "V2XM"
    UPER(V2XCaptureMetadata)
```

For DSRC, EPB packet data remains:

```text
Radiotap -> IEEE 802.11p / WAVE
```

The base metadata is self-contained per EPB. It can include observer
state, RAT context, and analysis only when each is available or was run.
The writer omits optional fields/categories rather than emitting empty
placeholder structures.

## Storage decisions

### Implemented savings

1. **No duplicate timestamp.** The EPB's standard timestamp is used;
   there is no ASN.1 timestamp value in `V2XCaptureMetadata`.
2. **UPER only.** The structured base object, IDB object, and all
   profile-defined nested objects use UPER. There is no OER alternative.
3. **Sparse optional metadata.** Location/motion/radio/analysis fields
   are omitted when unavailable, inapplicable, or not evaluated.
4. **Stable context at IDB level.** Interface time semantics and stable
   interface context are written once per IDB rather than per EPB.

### Chosen non-saving: no correlated state blocks

Periodic observer-state records could save additional bytes for highly
repetitive location, motion, or time-quality data. They are not used in
this version because the profile requires self-contained EPB metadata.
Dynamic state therefore stays in the optional receive/transmit observation
of the EPB that it describes. No decoder inherits a prior EPB's state.

## Extensions

Profile-defined structures are UPER encoded. A regional or manufacturer
extension that is deliberately outside the base schema is carried as a
separate Custom Binary Option on the same EPB, using that owner's PEN.
Such third-party bytes are opaque to the base V2X profile.

```text
Regional or Manufacturer Custom Binary Option
    extension owner's IANA PEN (32 bits)
    extension profile ID and revision
    opaque extension bytes
```

Do not create a second EPB merely to attach an extension: it would be a
second packet record, not an attachment. A regional/manufacturer option
on the original EPB preserves the one-logical-packet model.

## RAT boundaries

- **DSRC:** preserves `Radiotap -> IEEE 802.11p/WAVE` packet data.
- **ARIB STD-T760:** uses its own small technology branch.
- **LTE-V2X:** carries PC5 Layer-2 IDs and PPPP only in the LTE branch.
- **NR-V2X:** carries PC5 Layer-2 IDs and NR QoS only in the NR branch.
- **LTE/NR lower layers:** provide summary values only: HARQ usage/count,
  optional RLC segment count, and optional RLC/PDCP error counts. The
  profile does not require raw RLC/PDCP bytes, transport-block rows,
  segment records, or HARQ-event lists.

## Analysis boundaries

The optional per-EPB `AnalysisAnnotations` field reports separate:

- cryptographic/credential **security validation**;
- receiver-context **relevance**;
- internal **consistency**;
- **Misbehavior Detection (MBD)**; and
- TX and RX application/stack annotations.

All analysis values are local results from an ITS stack, capture
producer, or post-capture analyzer. They are not on-air bytes and are
not signed packet data. TX congestion values are explicitly TX-side;
the receive container is reserved for receive-side stack results.

No category is mandatory. When present, each category contains explicit
attempted/processed/result semantics. The core does not require a
detector, check, or message-ID dictionary.

## Coordinate reference systems
Observer coordinates identify a **coordinate reference system**, not only
an assumed datum. The base values explicitly recognize WGS-84 and GCJ-02.
The `other` branch carries a UTF-8 `systemId` for any future regional,
transformed, encrypted/protected, or otherwise non-WGS-84 system. A tool
must not assume another system is WGS-84 or safely convertible without the
governing system specification. Latitude, longitude, and altitude always
use the same declared coordinate reference system.

## ASN.1 modules

| Module | Responsibility |
|---|---|
| `V2X-Capture-Common` | identifiers, availability, payload classification |
| `V2X-Capture-Time` | epoch, synchronization, EPB timestamp semantics |
| `V2X-Capture-Interface` | IDB-level interface/time metadata |
| `V2X-Capture-Observer` | location, motion, provenance, and RF observation |
| `V2X-Capture-DSRC` | DSRC/Radiotap-adjacent metadata |
| `V2X-Capture-ARIB-T760` | ARIB ITS-Connect metadata |
| `V2X-Capture-LTE-V2X` | LTE V2X PC5/SCI/summary metadata |
| `V2X-Capture-NR-V2X` | NR V2X PC5/SCI/summary metadata |
| `V2X-Capture-Analysis` | optional per-EPB analysis annotations |
| `V2X-Capture-Record` | compact per-EPB base metadata |

## Validation gate

`validate_asn.py` performs structural checks, import-symbol checks,
acyclic import-graph checks, and verifies the 70-character line limit.
It is not an ASN.1 compiler. The release gate remains compilation and
UPER encode/decode validation in OSS Nokalva ASN.1 Studio.
