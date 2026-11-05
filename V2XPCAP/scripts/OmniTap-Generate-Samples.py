#!/usr/bin/env python3
"""Generate reference OmniTap (Native) and OmniTap-Lua sample pcapng captures with real COER payloads.

It compiles the 12 normative OmniTap ASN.1 modules with asn1tools in OER/COER mode, encodes
representative CaptureContext, InterfaceContext, PacketMetadata (LTE-V2X, NR-V2X/A2X, ETSI ITS-G5,
and ITS Connect / ARIB STD-T109), and SupplementalResult objects, writes a canonical OmniTap (Native)
pcapng file (with PacketMetadata carried inside each EPB as Custom Binary Option 2989 / 0x0BAD),
converts it to OmniTap-Lua using scripts/OmniLuazer.py, and verifies round-trip identity and
COER decoding of every object.

Usage:
  python scripts/OmniTap-Generate-Samples.py [--out-dir samples] [--self-test]
"""

import argparse
import pathlib
import struct
import sys
import tempfile

import asn1tools

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import OmniLuazer  # noqa: E402

PEN = 32473  # RFC 5612 documentation PEN placeholder
SESSION_UUID = bytes.fromhex("018f4a2000007000800000007c115e90")
SESSION_TAG = 0x7C115E90
T0_NS = 1_730_640_000 * 1_000_000_000


def compile_omnitap_codec():
    asn_dir = ROOT / "asn" if (ROOT / "asn").is_dir() else ROOT
    modules = [str(p) for p in sorted(asn_dir.glob("*.asn"))]
    return asn1tools.compile_files(modules, "oer")


def encode_object(codec, body_choice: str, body_val: dict) -> bytes:
    obj = {
        "profileVersion": {"major": 1, "minor": 0},
        "body": (body_choice, body_val),
    }
    encoded = codec.encode("OmniTapObject", obj)
    # Round-trip decode check
    decoded = codec.decode("OmniTapObject", encoded)
    assert decoded["profileVersion"] == {"major": 1, "minor": 0}
    assert decoded["body"][0] == body_choice
    return encoded


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def make_opt(code: int, val: bytes) -> bytes:
    return struct.pack("<HH", code, len(val)) + pad4(val)


OPT_END = struct.pack("<HH", 0, 0)


def make_block(btype: int, body: bytes) -> bytes:
    body = pad4(body)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def make_custom_block(coer_bytes: bytes) -> bytes:
    return make_block(OmniLuazer.CB_COPY, struct.pack("<I", PEN) + coer_bytes)


def make_idb(linktype: int, if_name: str, tsresol: int = 9) -> bytes:
    opts = (
        make_opt(2, if_name.encode("utf-8"))
        + make_opt(9, bytes([tsresol]))
        + OPT_END
    )
    return make_block(1, struct.pack("<HHI", linktype, 0, 262144) + opts)


def make_epb(
    interface_id: int,
    ts_ns: int,
    pkt_bytes: bytes,
    record_id: int,
    meta_coer: bytes,
    direction: int = 1,
) -> bytes:
    """Build an OmniTap (Native) EPB with epb_flags, epb_packetid, and Custom Binary Option 2989."""
    pid = (SESSION_TAG << 32) | record_id
    ts_high = (ts_ns >> 32) & 0xFFFFFFFF
    ts_low = ts_ns & 0xFFFFFFFF
    header = struct.pack(
        "<IIIII", interface_id, ts_high, ts_low, len(pkt_bytes), len(pkt_bytes)
    )
    # epb_flags (code 2): bits 0..1 = direction (1 = inbound/RX, 2 = outbound/TX)
    opts = (
        make_opt(2, struct.pack("<I", direction & 0x3))
        + make_opt(OmniLuazer.OPT_EPB_PACKETID, struct.pack("<Q", pid))
        + make_opt(
            OmniLuazer.OPT_CUSTOM_BIN_COPY,
            struct.pack("<I", PEN) + meta_coer,
        )
        + OPT_END
    )
    return make_block(OmniLuazer.EPB_TYPE, header + pad4(pkt_bytes) + opts)


def build_native_sample_bytes(codec) -> tuple[bytes, list[bytes]]:
    """Build a multi-RAT V2X/A2X OmniTap (Native) capture and return (pcapng_bytes, all_coer_objects)."""
    coer_objects = []
    blocks = []

    # 1. Section Header Block (SHB)
    shb_opts = (
        make_opt(2, b"OmniAir Reference OBU/AVD Platform")
        + make_opt(3, b"Linux 6.6 RT-V2X")
        + make_opt(4, b"OmniTap 1.0 Reference Generator (COER)")
        + OPT_END
    )
    blocks.append(
        make_block(
            OmniLuazer.SHB_TYPE,
            struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + shb_opts,
        )
    )

    # 2. CaptureContext Custom Block (required at start of file)
    cap_coer = encode_object(
        codec,
        "capture",
        {
            "sessionId": SESSION_UUID,
            "testCampaignDetails": "OmniAir Plugfest V2X/A2X Multi-RAT Reference Capture",
            "testCaseId": "OAC-OMNITAP-REF-001",
            "scenarioName": "Intersection BSM + NR-V2X A2X UAV Direct C2/DAA + ITS-G5 CAM + ITS Connect",
        },
    )
    coer_objects.append(cap_coer)
    blocks.append(make_custom_block(cap_coer))

    # 3. IDBs (4 interfaces: 0=pc5-lte0, 1=pc5-nr0, 2=its-g5-0, 3=arib-t109-0)
    # Using LINKTYPE_RAW (101) / LINKTYPE_IEEE802_11_RADIOTAP (127) / LINKTYPE_WIRESHARK_UPPER_PDU (252)
    blocks.append(make_idb(252, "pc5-lte0", tsresol=9))
    blocks.append(make_idb(252, "pc5-nr0", tsresol=9))
    blocks.append(make_idb(127, "its-g5-0", tsresol=9))
    blocks.append(make_idb(252, "arib-t109-0", tsresol=9))

    # 4. InterfaceContext Custom Blocks for each interface
    if_defs = [
        (
            "pc5-lte0",
            "lteV2x",
            5915000,
            10000,
            {"lteRrcSnapshot": {"lteSpecificationRelease": "r16", "configurationOctets": b"\x38\x01\x02\x03"}},
        ),
        (
            "pc5-nr0",
            "nrV2x",
            5905000,
            20000,
            {"nrRrcSnapshot": {"nrSpecificationRelease": "r18", "configurationOctets": b"\x38\x18\xa2\x00"}},
        ),
        ("its-g5-0", "etsiItsG5", None, None, {}),
        ("arib-t109-0", "aribT109", 760000, 10000, {}),
    ]
    for if_name, tech, freq, bw, extra in if_defs:
        if_val = {
            "sessionTag": SESSION_TAG,
            "interfaceName": if_name,
            "contextGeneration": 1,
            "technology": tech,
            "timeContext": {
                "receiveTimestampPoint": "radioReceive",
                "transmitTimestampPoint": "otaStart",
                "timeQuality": {
                    "source": "gnss",
                    "state": "locked",
                    "uncertaintyNs": 25,
                    "sourceAgeUs": 150,
                    "utcGpsOffsetSeconds": -18,
                },
            },
            "provenance": {
                "observerId": b"OBU-REF-01",
                "captureSource": "overTheAir",
                "hardwareVersion": b"HW-2.1",
                "softwareVersion": b"SW-1.0.0",
            },
            "antennaSystem": [
                {"antennaIndex": 0, "gainDbiX10": 35, "antennaModel": b"V2X-Roof-Fin-1"},
                {"antennaIndex": 1, "gainDbiX10": 30, "antennaModel": b"V2X-Roof-Fin-2"},
            ],
        }
        if freq is not None:
            if_val["defaultCenterFrequencyKHz"] = freq
        if bw is not None:
            if_val["defaultBandwidthKHz"] = bw
        if_val.update(extra)
        if_coer = encode_object(codec, "interfaceContext", if_val)
        coer_objects.append(if_coer)
        blocks.append(make_custom_block(if_coer))

    # 5. Packet 1: LTE-V2X PC5 RX packet (IEEE 1609.2 / WSMP BSM)
    meta1 = encode_object(
        codec,
        "packetMetadata",
        {
            "recordId": 1,
            "sessionTag": SESSION_TAG,
            "payload": {"payloadKind": "nonIp", "nonIpFamilyId": "ieee1609"},
            "timeQuality": {"source": "gnss", "state": "locked", "uncertaintyNs": 20},
            "observerLocation": {
                "position": {
                    "coordinateReferenceSystem": "wgs84",
                    "latitudeE7": 373860517,
                    "longitudeE7": -1220838511,
                    "altitudeDm": 325,
                },
                "hepeCm": 45,
                "ageUs": 2500,
                "motion": {"speedCmPerSec": 1388, "headingDegX100": 9000, "verticalSpeedCmPerSec": 0},
            },
            "radio": {
                "antennaMeasurements": [
                    {"antennaIndex": 0, "rssiDbmX10": -685, "rsrpDbmX10": -812, "rsrqDbX10": -95, "sinrDbX10": 165},
                    {"antennaIndex": 1, "rssiDbmX10": -710, "rsrpDbmX10": -840, "rsrqDbX10": -105, "sinrDbX10": 140},
                ],
                "channelLoad": {"channelLoadKind": "channelBusyRatio", "valuePercentX100": 1850, "measurementWindowUs": 100000},
                "centerFrequencyKHz": 5915000,
                "bandwidthKHz": 10000,
            },
            "technologyMetadata": (
                "lteV2x",
                {
                    "sidelinkTiming": {"systemFrameNumber": 512, "subframeNumber": 4},
                    "ltePc5Addressing": {
                        "lteSourceLayer2Id": b"\x0a\x1b\x2c",
                        "lteDestinationLayer2Id": b"\xff\xff\xff",
                        "pppp": 2,
                    },
                    "receivedSci1": {
                        "rawSciFormat1": b"\x42\x81\x10\x05",
                        "resourceReservationIntervalMs": 100,
                        "lteSchedulingMode": "semiPersistent",
                        "startSubchannelIndex": 0,
                        "priority": 1,
                        "frequencyResourceAssignment": 12,
                        "timeGap": 1,
                        "mcs": 7,
                        "retransmissionIndex": 0,
                    },
                    "lteLowerLayerSummary": {
                        "transportBlockCount": 1,
                        "rlcSegmentCount": 1,
                        "harqRetransmissionUsed": False,
                        "harqTransmissionCount": 1,
                    },
                },
            ),
        },
    )
    coer_objects.append(meta1)
    pkt1_bytes = b"\x03\x80\x20\x00\x10" + b"\x11" * 48  # Representative non-IP WSMP/1609 payload
    blocks.append(make_epb(0, T0_NS + 1_000_000, pkt1_bytes, 1, meta1, direction=1))

    # 6. Packet 2: NR-V2X / 3GPP Release 18 A2X PC5 TX packet (UAV observer at 120.0 m altitude climbing)
    meta2 = encode_object(
        codec,
        "packetMetadata",
        {
            "recordId": 2,
            "sessionTag": SESSION_TAG,
            "payload": {"payloadKind": "nonIp", "nonIpFamilyId": "ieee1609"},
            "observerLocation": {
                "position": {
                    "coordinateReferenceSystem": "wgs84",
                    "latitudeE7": 373862000,
                    "longitudeE7": -1220837000,
                    "altitudeDm": 1200,  # 120.0 m aerial A2X observer altitude
                },
                "hepeCm": 30,
                "motion": {"speedCmPerSec": 2250, "headingDegX100": 4500, "verticalSpeedCmPerSec": 350},
            },
            "radio": {
                "transmitAntennaIndex": 0,
                "transmitPowerDbmX10": 230,
                "channelLoad": {"channelLoadKind": "channelBusyRatio", "valuePercentX100": 1200},
                "centerFrequencyKHz": 5905000,
                "bandwidthKHz": 20000,
            },
            "technologyMetadata": (
                "nrV2x",
                {
                    "nrSidelinkTiming": {
                        "directFrameNumber": 240,
                        "slotIndex": 11,
                        "subcarrierSpacing": "scs30kHz",
                        "nrStartSubchannelIndex": 2,
                        "allocatedSubchannelCount": 4,
                    },
                    "nrPc5Addressing": {
                        "nrSourceLayer2Id": b"\xa2\x18\x01",
                        "nrDestinationLayer2Id": b"\xff\xff\xff",
                        "nrL1Priority": 1,
                    },
                    "nrSchedulingMode": "semiPersistent",
                    "resourceReservationIntervalMs": 100,
                    "sciStage1": {
                        "rawSciStage1": b"\x11\x22\x33\x44\x55",
                        "nrSciPriority": 0,
                        "nrFrequencyResourceAssignment": 18,
                        "nrTimeResourceAssignment": 5,
                        "nrResourceReservationPeriodMs": 100,
                        "sciStage2Format": "sciFormat2B",
                        "dmrsPortCount": 2,
                        "nrMcs": 9,
                        "psfchOverheadIndication": True,
                    },
                    "sciStage2": {
                        "rawSciStage2": b"\xaa\xbb\xcc\xdd\xee",
                        "harqProcessNumber": 3,
                        "newDataIndicator": True,
                        "redundancyVersion": 0,
                        "sourceIdL1": 0x01,
                        "destinationIdL1": 0xFFFF,
                        "harqFeedbackEnabled": True,
                        "castType": "groupcastNackOnly",
                        "zoneId": 1024,
                        "communicationRangeIndex": 6,
                        "communicationRangeRequirementM": 300,
                    },
                    "psfchFeedback": {"psfchOutcome": "dtxNoFeedback", "psfchSlotOffset": 2},
                    "mode2TxDiagnostics": {
                        "finalRsrpThresholdDbm": -104,
                        "rsrpThresholdRelaxationDb": 3,
                        "totalCandidateResources": 80,
                        "remainingCandidateResources": 64,
                        "reEvaluationReselected": False,
                        "preEmptionReselected": False,
                        "reselectionCounter": 12,
                        "channelOccupancyRatioPercentX100": 450,
                    },
                },
            ),
        },
    )
    coer_objects.append(meta2)
    pkt2_bytes = b"\x03\x80\x25\x00\x14" + b"\x22" * 64
    blocks.append(make_epb(1, T0_NS + 2_000_000, pkt2_bytes, 2, meta2, direction=2))

    # 7. Packet 3: ETSI ITS-G5 (Radiotap + IEEE 802.11p QoS Data + GeoNetworking/BTP/CAM)
    meta3 = encode_object(
        codec,
        "packetMetadata",
        {
            "recordId": 3,
            "sessionTag": SESSION_TAG,
            "payload": {"payloadKind": "nonIp", "nonIpFamilyId": "etsiIts"},
            "observerLocation": {
                "position": {
                    "coordinateReferenceSystem": "wgs84",
                    "latitudeE7": 481351253,
                    "longitudeE7": 115819806,
                    "altitudeDm": 5190,
                },
            },
            "technologyMetadata": ("etsiItsG5", {}),
        },
    )
    coer_objects.append(meta3)
    # Minimal 8-octet Radiotap header (it_version=0, it_pad=0, it_len=8, it_present=0) + 802.11 QoS Data
    radiotap_and_80211 = b"\x00\x00\x08\x00\x00\x00\x00\x00" + b"\x88\x00\x00\x00" + b"\xff" * 6 + b"\x02\x11\x22\x33\x44\x55" + b"\xff" * 6 + b"\x10\x00\x00\x00\xaa\xaa\x03\x00\x00\x00\x89\x47" + b"\x33" * 32
    blocks.append(make_epb(2, T0_NS + 3_000_000, radiotap_and_80211, 3, meta3, direction=1))

    # 8. Packet 4: ITS Connect (ARIB STD-T109 24-octet MAC control + LLC/SNAP)
    meta4 = encode_object(
        codec,
        "packetMetadata",
        {
            "recordId": 4,
            "sessionTag": SESSION_TAG,
            "payload": {"payloadKind": "nonIp"},
            "radio": {"centerFrequencyKHz": 760000, "bandwidthKHz": 10000},
            "technologyMetadata": ("aribT109", {}),
        },
    )
    coer_objects.append(meta4)
    arib_frame = b"\x01" * 24 + b"\xaa\xaa\x03\x00\x00\x00\x00\x01" + b"\x44" * 32
    blocks.append(make_epb(3, T0_NS + 4_000_000, arib_frame, 4, meta4, direction=1))

    # 9. Asynchronous SupplementalResult for Packet 1 (IEEE 1609.2 verification + J3287 check)
    supp1 = encode_object(
        codec,
        "supplementalResult",
        {
            "sessionId": SESSION_UUID,
            "recordId": 1,
            "producer": {
                "pen": PEN,
                "productName": "OmniAir-Ref-Security-Verifier",
                "producerSoftwareVersion": "1.0.0",
            },
            "resultSequence": 1,
            "analysis": {
                "securityValidation": {
                    "status": {"result": "passed"},
                    "ieee1609Dot2Result": "success",
                },
                "relevance": {"status": {"result": "passed"}},
                "consistency": {"status": {"result": "passed"}},
                "misbehaviorDetectionAnnotation": {"status": {"result": "passed"}},
            },
        },
    )
    coer_objects.append(supp1)
    blocks.append(make_custom_block(supp1))

    return b"".join(blocks), coer_objects


def generate_samples(out_dir: pathlib.Path, quiet: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
    codec = compile_omnitap_codec()
    native_bytes, coer_objects = build_native_sample_bytes(codec)

    out_dir.mkdir(parents=True, exist_ok=True)
    native_path = out_dir / "omnitap-reference-v2x-a2x.pcapng"
    lua_path = out_dir / "omnitap-reference-v2x-a2x.omnitap-lua.pcapng"

    native_path.write_bytes(native_bytes)
    lua_bytes, stats = OmniLuazer.convert_stream(native_bytes, to_lua=True, pen=PEN)
    lua_path.write_bytes(lua_bytes)

    # Verify folding back to native produces byte-identical native capture
    folded_bytes, fold_stats = OmniLuazer.convert_stream(lua_bytes, to_lua=False, pen=PEN)
    assert folded_bytes == native_bytes, "Round-trip OmniLuazer conversion mismatch"
    assert stats["unpacked_to_lua"] == 4 and fold_stats["folded_to_native"] == 4

    if not quiet:
        print(f"Generated OmniTap (Native): {native_path} ({len(native_bytes)} bytes, 4 EPBs with Option 2989)")
        print(f"Generated OmniTap-Lua:      {lua_path} ({len(lua_bytes)} bytes, {len(coer_objects)} COER Custom Blocks)")
    return native_path, lua_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default=str(ROOT / "samples"), help="Output directory for sample pcapng files")
    parser.add_argument("--self-test", action="store_true", help="Run in temporary directory and verify COER round-trip")
    args = parser.parse_args()

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="omnitap-samples-") as tmp:
            native_path, lua_path = generate_samples(pathlib.Path(tmp), quiet=True)
            print("OmniTap-Generate-Samples self-test:")
            print(f"   Native file size: {native_path.stat().st_size} bytes (4 packets, 6 Custom Blocks)")
            print(f"   Lua file size:    {lua_path.stat().st_size} bytes (4 packets, 10 Custom Blocks, +32 B framing)")
            print("PASS: All 10 COER(OmniTapObject) payloads encoded, decoded, and round-tripped via OmniLuazer.")
        return 0

    generate_samples(pathlib.Path(args.out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())

