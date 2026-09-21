# V2X pcapng ASN.1 modules — ordered build set

## Canonical ordered modules

| File | Module role | Provisional module OID arc |
|---|---|---:|
| `00-V2X-Pcapng-Record.asn` | Top-level per-packet V2X metadata record | `record(0)` |
| `01-V2X-Pcapng-Common.asn` | Common observer/provenance/time/location/radio types | `common(1)` |
| `02-V2X-Pcapng-Radio.asn` | DSRC/Radiotap, ARIB, LTE-V2X, and NR-V2X branches | `radio(2)` |
| `03-V2X-Pcapng-Security.asn` | Security validation; relevance and consistency are security subcategories | `security(3)` |
| `04-V2X-Pcapng-Annotations.asn` | MBD and application congestion annotations | `annotations(4)` |

The `00-` prefix makes the top-level `Record` module appear first in alphabetical file listings. The record module uses `record(0)` as its terminal module OID arc. This ordinal is a **module/schema identifier only**; it is not the pcapng packet number.

## Important: resolve the current compiler error

The displayed error says the modules `V2X-Pcapng-Annotations` and `V2X-Pcapng-Analysis` have the same module OID. Build **only this ordered set**. Do not include an older `V2X-Pcapng-Analysis.asn` module in the same ASN.1 project unless it has a different module name and unique OID.

## OID status

`iso(1) identified-organization(3) v2x-pcapng-profile(99999)` remains a **provisional placeholder** for development. It must be replaced before publication with an OID allocated/controlled by the eventual standards owner or other authorized assigning authority. No OmniAir OID is assumed by this draft.

## Record ordering in pcapng

pcapng already gives records their order: the order of EPBs in the file. A per-packet `recordId` is optional metadata/correlation and should not be treated as the authoritative pcapng sequence number. A reader can derive the packet ordinal by scanning EPBs in file order.
