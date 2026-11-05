#!/usr/bin/env python3
"""OmniLuazer: Lossless bidirectional converter between OmniTap (Native) and OmniTap-Lua pcapng streams.

Why this tool exists:
- OmniTap (Native) is the primary standard format: per-packet PacketMetadata is carried inside each Enhanced Packet
  Block (EPB) as a copyable Custom Binary Option (option code 2989 / 0x0BAD). This keeps packet and metadata
  atomically bound through editcap, mergecap, deduplication, and Wireshark GUI packet exports, and is decoded
  natively by Wireshark builds compiled with the asn2wrs OmniTap C dissector.
- OmniTap-Lua is the compatibility stream for older or unmodified stock Wireshark/TShark installations running
  only the portable Lua dissector (.lua), because stock Wireshark's Lua API exposes standalone Custom Blocks
  (0x00000BAD) but not EPB Custom Binary Options.

Because both flavors carry the exact same COER(OmniTapObject) bytes, OmniLuazer converts between them without
touching packet bytes, timestamps, or ASN.1 encodings:
  --to-lua (default)   Unpacks EPB Custom Binary Option 2989 (OmniTap PEN) into a standalone copyable Custom Block
                       (0x00000BAD) immediately preceding the EPB.
  --to-native          Folds PacketMetadata Custom Blocks (0x00000BAD, CHOICE tag 0x82) back into the associated
                       EPB's Custom Binary Option 2989.
  --clean-orphans      Drops unassociated PacketMetadata / SupplementalResult Custom Blocks whose target EPB
                       (epb_packetid) is no longer present in the file (e.g., after editcap -d on an OmniTap-Lua file).
  --self-test          Runs a built-in round-trip verification test.

Usage:
    python scripts/OmniLuazer.py [--to-lua | --to-native] [--clean-orphans] [--pen PEN] INPUT.pcapng OUTPUT.pcapng
    python scripts/OmniLuazer.py --self-test
"""
import argparse
import pathlib
import struct
import sys
import tempfile

sys.stdout.reconfigure(errors="replace")

DEFAULT_PEN = 32473          # RFC 5612 documentation PEN placeholder
SHB_TYPE = 0x0A0D0D0A
EPB_TYPE = 0x00000006
CB_COPY = 0x00000BAD
CB_NOCOPY = 0x40000BAD
OPT_ENDOFOPT = 0
OPT_EPB_PACKETID = 5
OPT_CUSTOM_BIN_COPY = 2989   # 0x0BAD: copyable Custom Binary Option
CHOICE_PACKET_META = 0x82    # COER tag for OmniTapObjectBody.packetMetadata (3rd root alternative: 0x80, 0x81, 0x82)

_OER_CODEC = None


def _get_oer_codec():
    global _OER_CODEC
    if _OER_CODEC is None:
        try:
            import asn1tools
            root = pathlib.Path(__file__).resolve().parent.parent
            asn_dir = root / "asn" if (root / "asn").is_dir() else root
            _OER_CODEC = asn1tools.compile_files([str(p) for p in sorted(asn_dir.glob("*.asn"))], "oer")
        except Exception:
            _OER_CODEC = False
    return _OER_CODEC


def trim_coer_padding(payload: bytes) -> bytes:
    """Return exact unpadded COER(OmniTapObject) bytes from a 4-byte-padded Custom Block payload."""
    codec = _get_oer_codec()
    if codec:
        try:
            decoded = codec.decode("OmniTapObject", payload)
            reencoded = codec.encode("OmniTapObject", decoded)
            if payload.startswith(reencoded) and set(payload[len(reencoded):]) <= {0}:
                return reencoded
        except Exception:
            pass
    return payload


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def make_block(endian: str, block_type: int, body: bytes) -> bytes:
    padded = pad4(body)
    total = 12 + len(padded)
    return struct.pack(endian + "II", block_type, total) + padded + struct.pack(endian + "I", total)


def make_option(endian: str, code: int, value: bytes) -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + pad4(value)


def parse_options(raw_opts: bytes, endian: str) -> list[tuple[int, bytes]]:
    opts = []
    pos = 0
    while pos + 4 <= len(raw_opts):
        code, length = struct.unpack_from(endian + "HH", raw_opts, pos)
        if code == OPT_ENDOFOPT:
            break
        val = raw_opts[pos + 4:pos + 4 + length]
        opts.append((code, val))
        pos += 4 + length + (-length % 4)
    return opts


def serialize_options(opts: list[tuple[int, bytes]], endian: str) -> bytes:
    if not opts:
        return b""
    out = [make_option(endian, code, val) for code, val in opts]
    out.append(struct.pack(endian + "HH", OPT_ENDOFOPT, 0))
    return b"".join(out)


def parse_blocks(data: bytes) -> list[tuple[str, int, bytes]]:
    """Return list of (endian, block_type, body) across the pcapng byte stream."""
    blocks = []
    pos = 0
    endian = "<"
    while pos + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, pos)[0]
        if btype == SHB_TYPE:
            bom = data[pos + 8:pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        btype, total = struct.unpack_from(endian + "II", data, pos)
        if total < 12 or pos + total > len(data):
            raise ValueError(f"Invalid pcapng block length {total} at offset {pos}")
        body = data[pos + 8:pos + total - 4]
        blocks.append((endian, btype, body))
        pos += total
    return blocks


def epb_parts(body: bytes, endian: str) -> tuple[bytes, list[tuple[int, bytes]], int | None]:
    """Return (fixed_header_plus_padded_packet_data, options_list, epb_packetid)."""
    caplen = struct.unpack_from(endian + "I", body, 12)[0]
    pkt_end = 20 + caplen + (-caplen % 4)
    prefix = body[:pkt_end]
    opts = parse_options(body[pkt_end:], endian)
    pid = next((struct.unpack(endian + "Q", v)[0] for c, v in opts if c == OPT_EPB_PACKETID and len(v) == 8), None)
    return prefix, opts, pid


def extract_packet_id_from_coer(coer_payload: bytes) -> int | None:
    """Extract 64-bit (sessionTag << 32 | recordId) from COER(OmniTapObject) for packetMetadata or supplementalResult.

    COER layout of OmniTapObject (v1.x, root preamble 0x00, version preamble 0x00):
      octet 0: 0x00 (OmniTapObject extension bit = 0)
      octet 1: 0x00 (OmniTapProfileVersion extension bit = 0)
      octet 2: major (1)
      octet 3: minor (0..255)
      octet 4: CHOICE tag:
        0x82 = packetMetadata:
          octet 5: preamble (1 octet: 1 extension bit + 6 optional bits + 1 unused pad bit)
          octet 6..9: recordId (uint32 big-endian)
          octet 10..13: sessionTag (uint32 big-endian)
        0x83 = supplementalResult:
          octet 5: preamble (1 octet)
          octet 6..21: sessionId (16 octets; last 4 octets = sessionTag)
          octet 22..25: recordId (uint32 big-endian)
    """
    if len(coer_payload) >= 14 and coer_payload[0] == 0x00 and coer_payload[1] == 0x00 and coer_payload[4] == 0x82:
        record_id, session_tag = struct.unpack_from(">II", coer_payload, 6)
        return (session_tag << 32) | record_id
    if len(coer_payload) >= 26 and coer_payload[0] == 0x00 and coer_payload[1] == 0x00 and coer_payload[4] == 0x83:
        session_tag = struct.unpack_from(">I", coer_payload, 18)[0]
        record_id = struct.unpack_from(">I", coer_payload, 22)[0]
        return (session_tag << 32) | record_id
    return None


def convert_stream(data: bytes, to_lua: bool, clean_orphans: bool = False, pen: int = DEFAULT_PEN) -> tuple[bytes, dict]:
    blocks = parse_blocks(data)
    stats = {"epbs": 0, "unpacked_to_lua": 0, "folded_to_native": 0, "orphans_removed": 0}

    # Collect all EPB packet IDs present in the file (for orphan cleanup and native folding).
    epb_pids = set()
    for endian, btype, body in blocks:
        if btype == EPB_TYPE:
            _, _, pid = epb_parts(body, endian)
            if pid is not None:
                epb_pids.add(pid)

    if to_lua:
        out_chunks = []
        for endian, btype, body in blocks:
            if btype == EPB_TYPE:
                stats["epbs"] += 1
                prefix, opts, pid = epb_parts(body, endian)
                kept_opts = []
                extracted_payloads = []
                for code, val in opts:
                    if code == OPT_CUSTOM_BIN_COPY and len(val) > 4:
                        opt_pen = struct.unpack_from(endian + "I", val, 0)[0]
                        if opt_pen == pen:
                            extracted_payloads.append(val[4:])
                            continue
                    kept_opts.append((code, val))
                for payload in extracted_payloads:
                    cb_body = struct.pack(endian + "I", pen) + payload
                    out_chunks.append(make_block(endian, CB_COPY, cb_body))
                    stats["unpacked_to_lua"] += 1
                new_epb_body = prefix + serialize_options(kept_opts, endian)
                out_chunks.append(make_block(endian, EPB_TYPE, new_epb_body))
            elif btype in (CB_COPY, CB_NOCOPY) and clean_orphans and len(body) > 4:
                cb_pen = struct.unpack_from(endian + "I", body, 0)[0]
                if cb_pen == pen:
                    target_pid = extract_packet_id_from_coer(body[4:])
                    if target_pid is not None and target_pid not in epb_pids:
                        stats["orphans_removed"] += 1
                        continue
                out_chunks.append(make_block(endian, btype, body))
            else:
                out_chunks.append(make_block(endian, btype, body))
        return b"".join(out_chunks), stats

    # --to-native: fold PacketMetadata Custom Blocks (CHOICE tag 0x82) into their target EPB's Custom Binary Option 2989
    meta_by_pid: dict[int, list[bytes]] = {}
    remaining_blocks = []
    for endian, btype, body in blocks:
        if btype in (CB_COPY, CB_NOCOPY) and len(body) > 4:
            cb_pen = struct.unpack_from(endian + "I", body, 0)[0]
            payload = body[4:]
            if cb_pen == pen and len(payload) >= 14 and payload[0] == 0x00 and payload[1] == 0x00 and payload[4] == CHOICE_PACKET_META:
                target_pid = extract_packet_id_from_coer(payload)
                if target_pid is not None and target_pid in epb_pids:
                    meta_by_pid.setdefault(target_pid, []).append(trim_coer_padding(payload))
                    continue
                if clean_orphans and target_pid is not None and target_pid not in epb_pids:
                    stats["orphans_removed"] += 1
                    continue
            elif cb_pen == pen and clean_orphans:
                target_pid = extract_packet_id_from_coer(payload)
                if target_pid is not None and target_pid not in epb_pids:
                    stats["orphans_removed"] += 1
                    continue
        remaining_blocks.append((endian, btype, body))

    out_chunks = []
    for endian, btype, body in remaining_blocks:
        if btype == EPB_TYPE:
            stats["epbs"] += 1
            prefix, opts, pid = epb_parts(body, endian)
            if pid is not None and pid in meta_by_pid:
                for payload in meta_by_pid.pop(pid):
                    opts.append((OPT_CUSTOM_BIN_COPY, struct.pack(endian + "I", pen) + payload))
                    stats["folded_to_native"] += 1
            out_chunks.append(make_block(endian, EPB_TYPE, prefix + serialize_options(opts, endian)))
        else:
            out_chunks.append(make_block(endian, btype, body))
    return b"".join(out_chunks), stats


def self_test() -> bool:
    """Verify lossless conversion between OmniTap (Native) and OmniTap-Lua using real COER payloads."""
    import asn1tools
    root = pathlib.Path(__file__).resolve().parent.parent
    asn_dir = root / "asn" if (root / "asn").is_dir() else root
    spec = asn1tools.compile_files([str(p) for p in sorted(asn_dir.glob("*.asn"))], "oer")

    session_id = bytes.fromhex("0190000000007000800000007c115e90")
    tag = int.from_bytes(session_id[-4:], "big")
    cap_coer = spec.encode("OmniTapObject", {"profileVersion": {"major": 1, "minor": 0}, "body": ("capture", {"sessionId": session_id})})
    meta_coer = spec.encode("OmniTapObject", {
        "profileVersion": {"major": 1, "minor": 0},
        "body": ("packetMetadata", {"recordId": 1, "sessionTag": tag}),
    })
    # Ensure meta_coer length is a multiple of 4 or test padding resilience
    endian = "<"
    shb = make_block(endian, SHB_TYPE, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = make_block(endian, 1, struct.pack("<HHI", 1, 0, 65535) + serialize_options([(2, b"pc5-0"), (9, b"\x06")], endian))
    cap_cb = make_block(endian, CB_COPY, struct.pack("<I", DEFAULT_PEN) + cap_coer)

    pid = (tag << 32) | 1
    frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x88\xb5" + b"V2X" * 10
    epb_prefix = struct.pack("<IIIII", 0, 0, 1000, len(frame), len(frame)) + pad4(frame)
    native_opts = [(OPT_EPB_PACKETID, struct.pack("<Q", pid)), (OPT_CUSTOM_BIN_COPY, struct.pack("<I", DEFAULT_PEN) + meta_coer)]
    native_epb = make_block(endian, EPB_TYPE, epb_prefix + serialize_options(native_opts, endian))
    native_stream = shb + idb + cap_cb + native_epb

    lua_stream, s1 = convert_stream(native_stream, to_lua=True)
    roundtrip_stream, s2 = convert_stream(lua_stream, to_lua=False)

    ok_to_lua = s1["epbs"] == 1 and s1["unpacked_to_lua"] == 1
    ok_to_native = s2["epbs"] == 1 and s2["folded_to_native"] == 1
    print(f"   OmniTap Native -> OmniTap-Lua unpacked: {s1['unpacked_to_lua']} packet(s)  ({'yes' if ok_to_lua else 'NO'})")
    print(f"   OmniTap-Lua -> OmniTap Native folded:   {s2['folded_to_native']} packet(s)  ({'yes' if ok_to_native else 'NO'})")
    return ok_to_lua and ok_to_native


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--to-lua", action="store_true", help="convert OmniTap (Native) to OmniTap-Lua (default)")
    mode.add_argument("--to-native", action="store_true", help="convert OmniTap-Lua back to OmniTap (Native)")
    parser.add_argument("--clean-orphans", action="store_true", help="remove unassociated PacketMetadata / SupplementalResult Custom Blocks")
    parser.add_argument("--pen", type=int, default=DEFAULT_PEN, help=f"OmniTap PEN (default: {DEFAULT_PEN})")
    parser.add_argument("--self-test", action="store_true", help="run built-in self-test")
    parser.add_argument("input", nargs="?", help="input .pcapng file")
    parser.add_argument("output", nargs="?", help="output .pcapng file")
    args = parser.parse_args()

    if args.self_test:
        print("OmniLuazer self-test:")
        ok = self_test()
        print("PASS: OmniLuazer round-trip verified." if ok else "FAIL: OmniLuazer self-test failed.")
        return 0 if ok else 1

    if not args.input or not args.output:
        parser.error("INPUT.pcapng and OUTPUT.pcapng are required unless --self-test is specified.")

    to_lua = not args.to_native
    in_path = pathlib.Path(args.input)
    out_path = pathlib.Path(args.output)
    out_bytes, stats = convert_stream(in_path.read_bytes(), to_lua=to_lua, clean_orphans=args.clean_orphans, pen=args.pen)
    out_path.write_bytes(out_bytes)
    direction = "OmniTap -> OmniTap-Lua" if to_lua else "OmniTap-Lua -> OmniTap (Native)"
    print(
        f"PASS ({direction}): {stats['epbs']} EPB(s); "
        f"unpacked={stats['unpacked_to_lua']}, folded={stats['folded_to_native']}, "
        f"orphans_removed={stats['orphans_removed']} -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

