# OmniAir OmniTap — Draft V2X Capture Metadata Profile

## Goals

- Use standard **pcapng**; do not define a new capture-file format.
- Keep an EPB as the single standard record for one logical V2X packet.
- Preserve RAT-native bytes. DSRC remains `Radiotap → IEEE 802.11p/WAVE`.
- Use PEN-owned pcapng **Custom Blocks** as the sole structured OmniTap carriage, so a portable Wireshark Lua implementation can inspect the metadata.
- Use UPER for all structured OmniTap objects. Opaque regional/manufacturer extensions are bounded and optional.
- Provide a public, versioned, independently implementable profile suitable for an open-source Wireshark dissector.

## pcapng hierarchy

```text
SHB
├─ OmniTap Capture-Context Custom Block
│  └─ UPER(V2XCaptureContext): session, campaign, test case, scenario
├─ IDB
│  └─ standard pcapng fields: LinkType, name, timestamp resolution, etc.
├─ OmniTap Interface-Context Custom Block
│  └─ UPER(V2XInterfaceContext): interface baseline and timing semantics
├─ OmniTap Packet-Metadata Custom Block
│  └─ UPER(V2XPacketMetadata): target interface, EPB ordinal, recordId
├─ EPB
│  └─ authoritative timestamp and native packet bytes
└─ OmniTap Supplemental-Result Custom Block (optional)
   └─ UPER(V2XSupplementalResult): delayed analysis only
```

## Association rule

A Packet-Metadata Custom Block **shall immediately precede** its EPB. It shall carry the target pcapng interface ID and the one-based EPB ordinal within the section. Readers validate adjacency, interface ID, and ordinal. `recordId` is the stable key used by a later Supplemental-Result block.

## Presence and saturation

An absent optional field makes **no assertion**. It may mean unknown, unavailable, not exposed, not decoded, not applicable, or otherwise not provided. The only exceptions are required association/time fields, explicitly inherited Interface-Context defaults, and values documented as saturated. For a documented saturating count, the maximum value means **that value or more**.

## Time

The standard EPB timestamp is the only packet timestamp. Interface Context requires `timeEpoch` of UTC, GPS, or TAI. `other` and `unknown` are not baseline values. Dynamic synchronization quality is optional Packet Metadata.

## Lua implementation goal

OmniTap is intended to be practical for a portable Lua reference dissector. Wireshark 4.6.9 experiments showed Lua can inspect Custom Blocks and their PEN payloads, while tested IDB/EPB Custom Binary Options were not Lua-visible. A native dissector may later be provided for upstream performance and integration.
