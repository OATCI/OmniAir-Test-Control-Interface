#!/usr/bin/env python3
"""Test what the Wireshark command-line tools do to OmniTap (Native) and OmniTap-Lua pcapng files.

It builds small pcapng files by hand (no extra libraries) in both stream flavors:
  - OmniTap (Native): PacketMetadata carried inside each EPB as Custom Binary Option 2989 (0x0BAD).
  - OmniTap-Lua:      PacketMetadata carried in a standalone Custom Block (0x00000BAD) preceding each EPB.

It runs mergecap, editcap, reordercap and tshark from the installed Wireshark on them, then reads every output file
back and reports what survived: the epb_packetid option, the EPB Custom Binary Option (2989) in OmniTap Native files,
the standalone Custom Blocks in OmniTap-Lua files, the interface name, and the Interface Description Blocks.
Usage: python scripts/OmniTap-Survival-Test.py [--wireshark-dir DIR] [--keep]
"""
import argparse
import collections
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(errors="replace")

PEN = 32473  # RFC 5612 documentation PEN used by OmniTap development and test artifacts
CB_COPY = 0x00000BAD
OPT_CUSTOM_BINARY_COPY = 2989  # 0x0BAD
TAG_A = 0x7C115E90
TAG_B = 0x3A9F0C21
T0_NS = 1_700_000_000 * 1_000_000_000
KINDS = {"C": "capture-context", "I": "interface-context", "P": "packet-metadata", "S": "supplemental-result"}


# ---------------------------------------------------------------- writing
def pad4(data):
    return data + b"\0" * (-len(data) % 4)


def block(block_type, body):
    body = pad4(body)
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def option(code, value):
    return struct.pack("<HH", code, len(value)) + pad4(value)


END = struct.pack("<HH", 0, 0)


def otap_payload(kind, key, extra=b""):
    return b"OTAP" + kind.encode() + b"\0\0\0" + struct.pack(">Q", key) + extra


def custom(kind, key, extra=b""):
    return block(CB_COPY, struct.pack("<I", PEN) + otap_payload(kind, key, extra))
def build(path, tag, if_name, offset_ns, count=5, native=False):
    """One capture session: SHB, IDB, capture and interface context, then packets, then a result.
    If native=True, PacketMetadata is placed inside EPB Option 2989 (OmniTap Native);
    if native=False, PacketMetadata is a standalone Custom Block before each EPB (OmniTap-Lua).
    """
    out = [block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + option(4, b"OmniTap survival test") + END)]
    out.append(block(1, struct.pack("<HHI", 1, 0, 262144) + option(2, if_name.encode()) + option(9, b"\x09") + END))
    out.append(custom("C", tag << 32))
    out.append(custom("I", tag << 32, if_name.encode()))
    for n in range(1, count + 1):
        pid = (tag << 32) | n
        ts = T0_NS + n * 1_000_000 + offset_ns
        frame = bytes.fromhex("ffffffffffff0200000000") + bytes([n]) + b"\x88\xb5" + bytes([n]) * 46
        epb = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + pad4(frame)
        epb_opts = option(5, struct.pack("<Q", pid))
        if native:
            epb_opts += option(OPT_CUSTOM_BINARY_COPY, struct.pack("<I", PEN) + otap_payload("P", pid))
        else:
            out.append(custom("P", pid))
        out.append(block(6, epb + epb_opts + END))
    out.append(custom("S", (tag << 32) | 3))
    pathlib.Path(path).write_bytes(b"".join(out))


# ---------------------------------------------------------------- reading
def options(data, endian):
    found, pos = [], 0
    while pos + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, pos)
        if code == 0:
            break
        found.append((code, data[pos + 4:pos + 4 + length]))
        pos += 4 + length + (-length % 4)
    return found


def read(path):
    data = pathlib.Path(path).read_bytes()
    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    pos, idbs, epbs, cbs, order = 0, [], [], [], []
    while pos < len(data):
        btype, total = struct.unpack_from(endian + "II", data, pos)
        body = data[pos + 8:pos + total - 4]
        if btype == 0x0A0D0D0A:
            order.append("H")
        elif btype == 1:
            name = next((v.decode("utf-8", "replace") for c, v in options(body[8:], endian) if c == 2), None)
            idbs.append(name)
            order.append("D")
        elif btype == 6:
            iface, _, _, caplen, _ = struct.unpack_from(endian + "IIIII", body, 0)
            opts = options(body[20 + caplen + (-caplen % 4):], endian)
            pid = next((struct.unpack(endian + "Q", v)[0] for c, v in opts if c == 5 and len(v) == 8), None)
            opt2989_keys = [
                struct.unpack(">Q", v[12:20])[0]
                for c, v in opts
                if c == OPT_CUSTOM_BINARY_COPY and len(v) >= 20 and struct.unpack_from(endian + "I", v, 0)[0] == PEN and v[4:8] == b"OTAP"
            ]
            epbs.append((iface, pid, opt2989_keys))
            order.append("E")
        elif btype in (CB_COPY, 0x40000BAD):
            payload = body[4:]
            if payload[:4] == b"OTAP":
                kind, key = chr(payload[4]), struct.unpack(">Q", payload[8:16])[0]
                extra = payload[16:].rstrip(b"\0").decode("utf-8", "replace")
            else:
                kind, key, extra = "?", None, ""
            cbs.append((kind, key, extra))
            order.append(kind.lower())
        else:
            order.append("<%x>" % btype)
        pos += total
    return {"idbs": idbs, "epbs": epbs, "cbs": cbs, "order": order}


def sequence(order):
    text = "".join(order)
    text = re.sub(r"((?:pE)+)", lambda m: "(pE)x%d" % (len(m.group(1)) // 2) if len(m.group(1)) > 2 else m.group(1), text)
    return re.sub(r"(E{3,})", lambda m: "Ex%d" % len(m.group(1)), text)


def describe(label, parsed, indent="    "):
    epbs, cbs, order = parsed["epbs"], parsed["cbs"], parsed["order"]
    pids = [p for _, p, _ in epbs if p is not None]
    epb_pids = set(pids)
    opt2989_ok = sum(1 for _, p, keys in epbs if p is not None and keys == [p])
    counts = collections.Counter(k for k, _, _ in cbs)
    adjacent = sum(1 for i, o in enumerate(order[:-1]) if o == "p" and order[i + 1] == "E")
    adj_ok = 0
    epb_index = [i for i, o in enumerate(order) if o == "E"]
    cb_positions = [i for i, o in enumerate(order) if o in "cips?"]
    cb_iter = iter(cbs)
    keyed = {}
    for pos in cb_positions:
        keyed[pos] = next(cb_iter)
    epb_iter = iter(epbs)
    epb_at = {pos: next(epb_iter) for pos in epb_index}
    for pos, (kind, key, _) in keyed.items():
        if kind == "P" and order[pos + 1:pos + 2] == ["E"] and epb_at[pos + 1][1] == key:
            adj_ok += 1
    wrong = adjacent - adj_ok
    contexts = {(key >> 32, extra) for k, key, extra in cbs if k == "I"}
    per_epb = sum(1 for i, p, _ in epbs if p is not None and (p >> 32, parsed["idbs"][i]) in contexts)
    per_idb = 0
    for index, name in enumerate(parsed["idbs"]):
        tags = {p >> 32 for i, p, _ in epbs if i == index and p is not None}
        if len(tags) == 1 and (next(iter(tags)), name) in contexts:
            per_idb += sum(1 for i, p, _ in epbs if i == index and p is not None)
    unassoc_p = sum(1 for k, key, _ in cbs if k == "P" and key not in epb_pids)
    unassoc_s = sum(1 for k, key, _ in cbs if k == "S" and key not in epb_pids)
    dup = len(pids) - len(epb_pids)
    sessions = []
    for index, name in enumerate(parsed["idbs"]):
        tags = sorted({p >> 32 for i, p, _ in epbs if i == index and p is not None})
        sessions.append("IDB%d[%s]: %d session tag%s" % (index, name, len(tags), "" if len(tags) == 1 else "s"))
    print("%s%s" % (indent, label))
    print("%s  IDBs: %d %s" % (indent, len(parsed["idbs"]), parsed["idbs"]))
    print("%s  EPBs: %d, with epb_packetid: %d, with EPB Option 2989 (OmniTap Native): %d, repeated ids: %d"
          % (indent, len(epbs), len(pids), opt2989_ok, dup))
    print("%s  Custom Blocks: capture %d, interface %d, packet %d, result %d, other %d"
          % (indent, counts["C"], counts["I"], counts["P"], counts["S"], counts["?"]))
    if counts["P"]:
        print("%s  Packet Metadata CB directly before its EPB: %d of %d; without a matching EPB: %d; results without one: %d"
              % (indent, adj_ok, counts["P"], unassoc_p, unassoc_s))
        print("%s  Packet Metadata CB next to an EPB but for a DIFFERENT packet: %d" % (indent, wrong))
    print("%s  Sessions per IDB: %s" % (indent, "; ".join(sessions) if sessions else "none"))
    print("%s  EPBs that find their Interface Context: per EPB (sessionTag + if_name) %d of %d; per IDB (one session) %d of %d"
          % (indent, per_epb, len(epbs), per_idb, len(epbs)))
    print("%s  Block order: %s" % (indent, sequence(order)))
    return adjacent


# ---------------------------------------------------------------- running
def find_tools(directory):
    base = pathlib.Path(directory) if directory else None
    tools = {}
    for name in ("mergecap", "editcap", "reordercap", "tshark"):
        found = (base / (name + ".exe")) if base and (base / (name + ".exe")).exists() else None
        found = found or shutil.which(name)
        if not found:
            sys.exit("Cannot find %s. Use --wireshark-dir." % name)
        tools[name] = str(found)
    return tools


def run(args):
    proc = subprocess.run([str(a) for a in args], capture_output=True, text=True, errors="replace")
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--wireshark-dir", default=r"C:\Program Files\Wireshark")
    parser.add_argument("--keep", action="store_true", help="keep the generated files and print their directory")
    opts = parser.parse_args()
    tools = find_tools(opts.wireshark_dir)
    work = pathlib.Path(tempfile.mkdtemp(prefix="omnitap-survival-"))
    print("Tools:")
    for name, path in tools.items():
        print("  %-10s %s" % (name, run([path, "--version"])[1].splitlines()[0]))

    # 1. Verify OmniTap (Native: EPB Option 2989) survival across mergecap, editcap -d, and tshark -Y
    an, bn = work / "A_native.pcapng", work / "B_native.pcapng"
    build(an, TAG_A, "pc5-0", 0, native=True)
    build(bn, TAG_B, "pc5-0", 500_000, native=True)
    print("\n=== OmniTap (Native: EPB Option 2989) ===")
    describe("A_native.pcapng", read(an))
    pid = lambda tag, n: (tag << 32) | n
    native_cases = [
        ("mergecap A_native B_native (chronological)", [tools["mergecap"], "-F", "pcapng", "-w", work / "mn_all.pcapng", an, bn], work / "mn_all.pcapng"),
        ("mergecap A_native A_native (duplicate merge)", [tools["mergecap"], "-F", "pcapng", "-w", work / "mn_self.pcapng", an, an], work / "mn_self.pcapng"),
        ("editcap -d on A_native+A_native (deduplicate: 0 orphan PacketMetadata)", [tools["editcap"], "-F", "pcapng", "-d", work / "mn_self.pcapng", work / "en_dedup.pcapng"], work / "en_dedup.pcapng"),
        ("tshark -Y -w on A_native (subset export keeps EPB Option 2989 automatically)",
         [tools["tshark"], "-r", an, "-Y", "frame.packet_id == %d || frame.packet_id == %d" % (pid(TAG_A, 2), pid(TAG_A, 4)),
          "-F", "pcapng", "-w", work / "tn_filter.pcapng"], work / "tn_filter.pcapng"),
    ]
    for label, cmd, outpath in native_cases:
        rc, out, err = run(cmd)
        print("\n  %s  (exit %d)" % (label, rc))
        if outpath.exists():
            describe("output", read(outpath), "    ")

    # 2. Verify OmniTap-Lua (Custom Block 0x00000BAD) survival
    a, b, b2 = work / "A.pcapng", work / "B.pcapng", work / "B2.pcapng"
    build(a, TAG_A, "pc5-0", 0)
    build(b, TAG_B, "pc5-0", 500_000)  # same interface name as A, interleaved in time
    build(b2, TAG_B, "pc5-1", 500_000)  # different interface name
    print("\n=== OmniTap-Lua (Custom Block 0x00000BAD) Inputs ===")
    for path in (a, b, b2):
        describe(path.name, read(path))

    # sanity: Wireshark itself must read the hand-built file, and see epb_packetid
    rc, out, err = run([tools["tshark"], "-r", a, "-T", "fields", "-e", "frame.number", "-e", "frame.packet_id"])
    shown = [line.split("\t") for line in out.splitlines()]
    expect = [str((TAG_A << 32) | n) for n in range(1, 6)]
    with_id = [row[1] for row in shown if len(row) > 1 and row[1]]
    ok = rc == 0 and with_id == expect
    print("\nSanity: tshark reads A.pcapng. Frames listed: %d (5 packets + %d Custom Blocks). frame.packet_id correct on all 5"
          " packets: %s" % (len(shown), len(shown) - len(with_id), "yes" if ok else "NO"))
    print("  Frame numbers of the Custom Blocks and packets: %s"
          % " ".join(("P" if len(row) > 1 and row[1] else "c") for row in shown))
    if not ok:
        print("  rc=%s out=%r err=%r" % (rc, out, err))
        return 1

    lo, hi = TAG_B << 32, (TAG_B + 1) << 32
    cases = [
        ("mergecap A B (default IDB mode 'all')", ["mergecap", "-F", "pcapng"], [a, b], "m_all"),
        ("mergecap -I none A B", ["mergecap", "-F", "pcapng", "-I", "none"], [a, b], "m_none"),
        ("mergecap -I any A B", ["mergecap", "-F", "pcapng", "-I", "any"], [a, b], "m_any"),
        ("mergecap -a (append) A B", ["mergecap", "-F", "pcapng", "-a"], [a, b], "m_append"),
        ("mergecap A B2 (different interface names)", ["mergecap", "-F", "pcapng"], [a, b2], "m_names"),
        ("mergecap A A (the same file twice)", ["mergecap", "-F", "pcapng"], [a, a], "m_self"),
    ]
    results = {}
    print("\n=== mergecap (OmniTap-Lua) ===")
    for label, head, inputs, stem in cases:
        outfile = work / (stem + ".pcapng")
        rc, out, err = run([tools[head[0]]] + head[1:] + ["-w", outfile] + inputs)
        print("\n  %s  (exit %d)" % (label, rc))
        if err:
            print("    tool said: %s" % err.splitlines()[0])
        if outfile.exists():
            results[stem] = outfile
            describe("output", read(outfile), "    ")

    print("\n=== editcap, reordercap, tshark (OmniTap-Lua) ===")
    others = [
        ("editcap: plain rewrite of A", [tools["editcap"], "-F", "pcapng", a, work / "e_copy.pcapng"], "e_copy"),
        # Wireshark numbers every block that becomes a frame, Custom Blocks included. In A.pcapng the frames are:
        #   1 capture ctx, 2 interface ctx, 3 meta1, 4 EPB1, 5 meta2, 6 EPB2, 7 meta3, 8 EPB3, 9 meta4, 10 EPB4, 11 meta5,
        #   12 EPB5, 13 result.
        ("editcap -r: keep frames 5-10 of A (metadata and EPBs of packets 2, 3, 4)",
         [tools["editcap"], "-F", "pcapng", "-r", a, work / "e_keep.pcapng", "5-10"], "e_keep"),
        ("editcap: delete frames 4 and 8 of A (the EPBs of packets 1 and 3, not their metadata)",
         [tools["editcap"], "-F", "pcapng", a, work / "e_del.pcapng", "4", "8"], "e_del"),
        ("editcap -c 2: split A into files of 2 frames (frames include Custom Blocks)",
         [tools["editcap"], "-F", "pcapng", "-c", "2", a, work / "e_split.pcapng"], "e_split"),
        ("reordercap A", [tools["reordercap"], a, work / "r_copy.pcapng"], "r_copy"),
        ("tshark -w: plain rewrite of A", [tools["tshark"], "-r", a, "-F", "pcapng", "-w", work / "t_copy.pcapng"], "t_copy"),
        ("tshark -Y -w: keep packets 2 and 4 of A by frame.packet_id (the command-line twin of Export Specified Packets)",
         [tools["tshark"], "-r", a, "-Y", "frame.packet_id == %d || frame.packet_id == %d" % (pid(TAG_A, 2), pid(TAG_A, 4)),
          "-F", "pcapng", "-w", work / "t_filter.pcapng"], "t_filter"),
        ("tshark -Y -w: same, but the filter also accepts every OmniTap Custom Block (frame.cb_pen == %d)" % PEN,
         [tools["tshark"], "-r", a, "-Y", "frame.packet_id == %d || frame.packet_id == %d || frame.cb_pen == %d"
          % (pid(TAG_A, 2), pid(TAG_A, 4), PEN), "-F", "pcapng", "-w", work / "t_filter_cb.pcapng"], "t_filter_cb"),
    ]
    if "m_all" in results:
        others.append(("tshark -Y -w: keep only session B from the merged file",
                       [tools["tshark"], "-r", results["m_all"], "-Y", "frame.packet_id >= %d && frame.packet_id < %d" % (lo, hi),
                        "-F", "pcapng", "-w", work / "t_sessb.pcapng"], "t_sessb"))
    if "m_self" in results:
        others.append(("editcap -d: remove duplicates from the A+A merge",
                       [tools["editcap"], "-F", "pcapng", "-d", results["m_self"], work / "e_dedup.pcapng"], "e_dedup"))
    for label, command, stem in others:
        rc, out, err = run(command)
        print("\n  %s  (exit %d)" % (label, rc))
        if err:
            print("    tool said: %s" % err.splitlines()[0])
        files = sorted(work.glob(stem + ".pcapng")) + sorted(work.glob(stem + "_*.pcapng"))
        for index, path in enumerate(files):
            describe("output" + (" file %d" % (index + 1) if len(files) > 1 else ""), read(path), "    ")
        if not files:
            print("    no output file")

    if opts.keep:
        print("\nFiles kept in %s" % work)
    else:
        shutil.rmtree(work)
    return 0


if __name__ == "__main__":
    sys.exit(main())

