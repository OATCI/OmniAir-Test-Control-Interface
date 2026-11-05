# OmniTap Normative ASN.1 Modules (`asn/`)

This directory contains the 12 normative ASN.1 modules for OmniAir OmniTap V2X/A2X capture metadata. All modules use `EXPLICIT TAGS`, `AUTOMATIC TAGS`, and `EXTENSIBILITY IMPLIED`, and are serialized on the wire using **ASN.1 Canonical Octet Encoding Rules (`COER`, ITU-T X.696)**.

## Modules (Outside-In Order)

| File | ASN.1 Module Name | Scope |
|------|-------------------|-------|
| `00-OmniTap-Objects.asn` | `OmniTap-Objects` | Top-level envelope (`OmniTapObject`), profile version (`1.0`), `OmniTapCaptureContext`, and `OmniTapObjectBody` `CHOICE`. |
| `10-OmniTap-Interface-Context.asn` | `OmniTap-Interface-Context` | Per-interface context (`OmniTapInterfaceContext`), matched for each EPB by `(sessionTag, interfaceName)`. |
| `11-OmniTap-Time.asn` | `OmniTap-Time` | UTC clock quality (`TimeQuality`), synchronization state, and RX/TX timestamp reference points. |
| `12-OmniTap-Observer.asn` | `OmniTap-Observer` | Observer 3D position (`GeographicPosition` supporting V2X and A2X altitudes), coordinate reference system, motion, antennas, and `RadioObservation`. |
| `20-OmniTap-Packet-Metadata.asn` | `OmniTap-Packet-Metadata` | Per-EPB correlated metadata (`OmniTapPacketMetadata`), with one `TechnologyMetadata` branch per radio access technology. |
| `21-01-OmniTap-RAT-LTE-V2X.asn` | `OmniTap-RAT-LTE-V2X` | LTE-V2X PC5 (V2X and Release 18+ A2X): SFN/subframe timing, 24-bit L2 IDs, SCI Format 1, HARQ/RLC summary, and RRC snapshot. |
| `21-02-OmniTap-RAT-NR-V2X.asn` | `OmniTap-RAT-NR-V2X` | NR-V2X PC5 (V2X and Release 18+ A2X): DFN/slot timing, 24-bit L2 IDs, 1st- and 2nd-stage SCI, PSFCH feedback, Mode 2 sensing diagnostics, and RRC snapshot. |
| `21-03-OmniTap-RAT-ETSI-ITSG5.asn` | `OmniTap-RAT-ETSI-ITSG5` | ETSI ITS-G5 (IEEE 802.11p): extensible hook for facts not carried in Radiotap. |
| `21-04-OmniTap-RAT-ARIB-T109.asn` | `OmniTap-RAT-ARIB-T109` | ITS Connect (ARIB STD-T109): extensible hook for 760 MHz Japanese V2X metadata. |
| `30-OmniTap-Supplemental-Result.asn` | `OmniTap-Supplemental-Result` | Asynchronous correlated analysis (`OmniTapSupplementalResult`): IEEE 1609.2 verification, SAE J3287 observations, and producer identity. |
| `40-OmniTap-Extensions.asn` | `OmniTap-Extensions` | Structured `OptionalExtensions` container for regional and PEN-owned extensions. |
| `90-OmniTap-Common.asn` | `OmniTap-Common` | Common identifiers (`CaptureSessionId`, `SessionTag`, `RecordId`, `InterfaceName`), `V2xTechnology`, and payload classification. |

## Validation

From the `V2XPCAP` directory:

```text
python scripts/OmniTap-Validate.py
```
