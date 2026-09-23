# V2X Capture Metadata Profile — Commented ASN.1 Draft

## Scope and philosophy

This is an open V2X packet-capture metadata profile for normal pcapng
files. It does not change pcapng or replace native V2X packet bytes. One
EPB represents one logical V2X packet whenever practical. The profile
metadata is a separate, versioned ASN.1 object associated with that EPB.

`V2XCaptureMetadata` is always encoded using OER. The normal DSRC packet
representation stays `Radiotap -> IEEE 802.11p/WAVE`; no universal wrapper
is inserted before Radiotap. ARIB, LTE-V2X, and NR-V2X each have distinct
RAT modules. Common observer time, location, motion, RF, provenance,
analysis, and extension information remains external to native bytes.

The LTE/NR core is intentionally summary-oriented: no raw RLC/PDCP bytes,
no per-segment data, no per-TB records, and no HARQ-event list. It records
only whether HARQ was used and optionally reported transmission, segment,
and error counts.

## pcapng carriage

At write time, place the OER encoding of `V2XCaptureMetadata` in one
profile-defined EPB custom option. The existing pcapng custom-option
format carries its PEN. The profile bytes after that wrapper are planned as:

```text
"V2XM" | OER(V2XCaptureMetadata)
```

A PEN is just the global namespace identifier for the organization or
standards body governing custom-option bytes. It does not make pcapng,
the packet bytes, or this profile proprietary. The draft OID and final PEN
owner remain to be assigned before publication.

For annotations generated after capture, use a profile custom block or a
companion stream. The semantic join key is `sessionId + recordId`.
`correlationId`, time, packet index, or addresses are only supplemental.

## Time, location, and transmit semantics

All profile time is integral microseconds. `TimeEpoch` includes only UTC,
GPS, TAI, another documented epoch, or unknown. NTP, PTP, gPTP, GNSS, and
cellular network are synchronization sources, not epochs. `localOscillator`
is a source; `freeRunning` is a clock state indicating no active external
discipline. `holdover` means a previously disciplined local oscillator is
maintaining time after loss of a reference.

Coordinates use WGS-84 unless `datum=other` identifies another datum.
Altitude is in centimeters relative to the ellipsoid of that same datum.
Heading is degrees times 100, clockwise from true north; no alternate
heading reference is encoded. Both receive and transmit observations are
modeled. Tx timestamps carry a time point so packet creation, radio
submission, scheduling, OTA start, and completion are not confused.

## RAT placement

PC5 Layer-2 IDs and LTE PPPP are RAT-specific. They are not common payload
fields. LTE puts Layer-2 IDs and PPPP in its branch. NR puts PC5 Layer-2
IDs and PC5 QoS values in its branch; SCI-side Layer-1 IDs are separately
named. LTE PPPP and SCI priority are distinct concepts, and SCI priority
must not be interpreted as PPPP.

## Extension rule

The profile object itself is OER. An `ExtensionValue` is intentionally
opaque to the base profile. Its extension definition states whether the
stored octets are opaque, OER for an extension ASN.1 type, or UPER for an
extension ASN.1 type. The allowed values are exactly:

- `opaque` — bytes are interpreted only by the extension definition;
- `oer` — bytes encode that extension's ASN.1 type using OER; and
- `uper` — bytes encode that extension's ASN.1 type using UPER.

Regional and manufacturer extensions are held in independent containers.
A decoder can retain or ignore an unrecognized extension without changing
core-field meaning.

## Files

| File | Scope |
|---|---|
| `V2X-Capture-Common.asn` | IDs, availability, payload, extension definitions |
| `V2X-Capture-Observer.asn` | Rx/Tx time, position, motion, RF, provenance |
| `V2X-Capture-Analysis.asn` | Security, relevance, consistency, MBD, application |
| `V2X-Capture-DSRC.asn` | DSRC/Radiotap-adjacent metadata |
| `V2X-Capture-ARIB-T760.asn` | ARIB STD-T760 ITS-Connect metadata |
| `V2X-Capture-LTE-V2X.asn` | LTE PC5, SCI1, lower-layer summary |
| `V2X-Capture-NR-V2X.asn` | NR PC5, SCI, QoS, lower-layer summary |
| `V2X-Capture-Record.asn` | Top-level OER `V2XCaptureMetadata` |

