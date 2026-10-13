# V2X Capture Metadata Profile

## Purpose

This collection proposes an open, implementation-neutral metadata
profile for V2X packet capture. It uses existing **pcapng** structures;
it does not change pcapng or any on-air V2X protocol. The profile has
separate branches for DSRC/IEEE 802.11p, ARIB STD-T760 ITS-Connect,
LTE-V2X, and NR-V2X.

## Encoding and pcapng carriage

All profile-defined ASN.1 objects are encoded using **UPER**. The base
per-packet object is carried in one profile-defined pcapng Custom
Binary Option attached to its Enhanced Packet Block (EPB). The Custom
Binary Option begins with the profile steward's PEN and then carries
the profile envelope and the UPER object.

The standard EPB timestamp is the sole timestamp for each logical
packet. There is no duplicate ASN.1 packet timestamp. Each V2X-aware
IDB declares a 1 microsecond timestamp resolution, its `timeEpoch`,
and the RX/TX timestamp reference point. The `TimeQuality` object is
interface context and describes the clock used for EPB timestamps.

For DSRC, EPB packet data stays in native Wi-Fi order:

```text
Radiotap -> IEEE 802.11p / WAVE
```

The common metadata object is supplementary observer/capture metadata;
it does not precede Radiotap or modify native packet bytes.

## One logical V2X packet

One EPB represents one logical V2X packet. LTE-V2X and NR-V2X carry
only compact lower-layer summaries when a modem or driver provides
them: HARQ use/count, RLC segment count, and RLC/PDCP error counts.
The core does not carry raw RLC/PDCP bytes, individual segment rows,
transport-block records, or HARQ-event lists.

## Value-source philosophy

`MeasurementValue` and per-element availability wrappers are
intentionally absent. Each defined field has a fixed unit, range, and
normal source documented in its ASN.1 comment. A field that is not
included is simply not available at the capture point; zero is always a
real zero where zero is within the stated range.

A group may include optional `dataSource ValueSource` only where the
normal source can meaningfully vary. If omitted, the group uses its
commented default:

| Group | Default when `dataSource` is absent |
|---|---|
| `ObserverLocation.position` | `estimated` — a GNSS or other position solution is an estimate. |
| `ObserverMotion` | `estimated` — normally from the position/motion provider. |
| `TimeQuality` | `derived` — normally produced by the clock discipline system. |
| `ChannelLoad` | `derived` — normally calculated over its stated window. |
| DSRC/ARIB/SCI/QoS summaries | `observed` — normally decoded or reported by the radio/export. |
| LTE/NR lower-layer summary | `observed` — normally reported by modem/driver export. |

`dataSource` is used only to override one of those defaults, such as a
surveyed fixed observer position (`observed`) or a lower-layer summary
computed by capture software (`derived`). This retains provenance
without spending UPER bits on every value.

## Metadata placement

- **IDB profile option:** stable interface context, including time epoch
  and timestamp reference point.
- **EPB packet data:** native packet bytes.
- **EPB metadata option:** UPER-encoded `V2XCaptureMetadata` for the
  packet's observer, RAT-specific, and analysis data.
- **Custom external option/block:** optional opaque third-party content;
  it is not part of the profile-defined UPER object.

## RAT boundaries

Common payload classification does not contain PC5 addressing or PPPP.
LTE PC5 Layer-2 IDs and PPPP are in the LTE branch. NR PC5 Layer-2 IDs
and PC5 QoS observations are in the NR branch. DSRC continues to use
native Radiotap and 802.11/WAVE bytes.

## Modules

| File | Scope |
|---|---|
| `V2X-Capture-Common.asn` | IDs, classifications, value-source enum |
| `V2X-Capture-Time.asn` | epoch, time sync, timestamp semantics |
| `V2X-Capture-Interface.asn` | IDB-level V2X time context |
| `V2X-Capture-Observer.asn` | location, motion, provenance, RF data |
| `V2X-Capture-Analysis.asn` | validation, relevance, consistency, MBD, app |
| `V2X-Capture-DSRC.asn` | DSRC metadata; native bytes use Radiotap |
| `V2X-Capture-ARIB-T760.asn` | ARIB STD-T760 metadata |
| `V2X-Capture-LTE-V2X.asn` | LTE PC5, SCI1, compact lower-layer summary |
| `V2X-Capture-NR-V2X.asn` | NR PC5, SCI, compact lower-layer summary |
| `V2X-Capture-Record.asn` | top-level per-EPB metadata object |

## Draft status

The OIDs and final pcapng profile/PEN allocation remain provisional.
Use OSS Nokalva ASN.1 Studio for the authoritative syntax and UPER
compiler check before publication.
