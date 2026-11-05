#!/usr/bin/env python3
"""Install the third-party tools used by scripts/OmniTap-Validate.py.

Usage:
    python scripts/OmniTap-Setup.py [--ref REF] [--dest DIR] [--skip-pip] [--force]

What it does:
1. Installs or upgrades the asn1tools Python package with pip (into the active virtual environment if one is active,
   otherwise into the user site-packages).
2. Downloads Wireshark's ASN.1-to-C dissector generator, tools/asn2wrs.py, plus the PLY lexer/parser modules it
   imports (tools/lex.py and tools/yacc.py), into DEST (default: tools/wireshark).
   Source: the official Wireshark repository on GitLab, falling back to its read-only GitHub mirror.
   REF defaults to the tag of the installed Wireshark (for example v4.6.9), so asn2wrs matches the Wireshark version
   that will load the dissector. If no Wireshark is found, REF defaults to master.
   If the PLY modules are not in the Wireshark tree at REF, the ply package is installed with pip instead.
3. Writes DEST/SOURCE.txt recording the ref, URLs, and SHA-256 of every downloaded file, then runs a smoke test.

asn2wrs.py, lex.py, and yacc.py are third-party files under their own licenses (Wireshark: GPL-2.0-or-later; PLY:
BSD). They are downloaded for local use and are not OmniTap sources; do not commit or redistribute them.
"""
from pathlib import Path
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(errors="backslashreplace")

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [
    "https://gitlab.com/wireshark/wireshark/-/raw/{ref}/tools/{name}",
    "https://raw.githubusercontent.com/wireshark/wireshark/{ref}/tools/{name}",
]
TSHARK_CANDIDATES = ["tshark", r"C:\Program Files\Wireshark\tshark.exe", "/Applications/Wireshark.app/Contents/MacOS/tshark"]


def installed_wireshark_tag():
    """Return 'vX.Y.Z' for the installed Wireshark, or None."""
    for candidate in TSHARK_CANDIDATES:
        executable = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if not executable:
            continue
        try:
            output = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r"\b(\d+\.\d+\.\d+)\b", output)
        if match:
            return f"v{match.group(1)}"
    return None


def download(name, ref):
    """Return (bytes, url) for tools/<name> at ref, or (None, None) if no source has it."""
    for template in SOURCES:
        url = template.format(ref=ref, name=name)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "OmniTap-Setup"}),
                                        timeout=60) as response:
                return response.read(), url
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                print(f"  {url}: HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"  {url}: {exc}")
    return None, None


def pip_install(*packages):
    in_virtual_env = sys.prefix != getattr(sys, "base_prefix", sys.prefix) or "VIRTUAL_ENV" in os.environ
    command = [sys.executable, "-m", "pip", "install", "--upgrade", *([] if in_virtual_env else ["--user"]), *packages]
    print("Running:", " ".join(command))
    return subprocess.run(command).returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Install asn1tools and fetch Wireshark asn2wrs for OmniTap validation.")
    parser.add_argument("--ref", help="Wireshark git tag or branch (default: installed Wireshark version, else master)")
    parser.add_argument("--dest", default=str(ROOT / "tools" / "wireshark"), help="download directory")
    parser.add_argument("--skip-pip", action="store_true", help="do not install Python packages")
    parser.add_argument("--force", action="store_true", help="download again even if files exist")
    arguments = parser.parse_args()

    failures = []
    if not arguments.skip_pip:
        print("== asn1tools")
        if not pip_install("asn1tools"):
            failures.append("pip install asn1tools failed")

    ref = arguments.ref or installed_wireshark_tag() or "master"
    dest = Path(arguments.dest)
    dest.mkdir(parents=True, exist_ok=True)
    print(f"== asn2wrs from Wireshark ref {ref} -> {dest}")

    record = [f"Wireshark ref: {ref}", "Files are third-party; do not commit or redistribute.", ""]
    wanted = ["asn2wrs.py"]
    fetched = set()
    while wanted:
        name = wanted.pop(0)
        if name in fetched:
            continue
        fetched.add(name)
        target = dest / name
        if target.exists() and not arguments.force:
            data, url = target.read_bytes(), "(existing file kept; use --force to refresh)"
        else:
            data, url = download(name, ref)
            if data is None:
                if name == "asn2wrs.py":
                    failures.append(f"could not download tools/asn2wrs.py at ref {ref}")
                    break
                print(f"  tools/{name} not found at {ref}; will use the ply package instead")
                continue
            target.write_bytes(data)
        print(f"  {name}: {len(data)} bytes")
        record.append(f"{name}  sha256={hashlib.sha256(data).hexdigest()}  {url}")
        if name == "asn2wrs.py":
            source = data.decode("utf-8", errors="replace")
            for module in ("lex", "yacc"):
                if re.search(rf"^\s*(?:import\s+{module}\b|from\s+{module}\s+import)", source, re.M):
                    wanted.append(f"{module}.py")
            if re.search(r"^\s*(?:from\s+ply\b|import\s+ply\b)", source, re.M) and not arguments.skip_pip:
                if not pip_install("ply"):
                    failures.append("pip install ply failed")

    if (dest / "asn2wrs.py").exists():
        needs_ply = [m for m in ("lex", "yacc") if f"{m}.py" in fetched and not (dest / f"{m}.py").exists()]
        if needs_ply and not arguments.skip_pip and not pip_install("ply"):
            failures.append("pip install ply failed")
        (dest / "SOURCE.txt").write_text("\n".join(record) + "\n", encoding="utf-8")
        smoke = subprocess.run([sys.executable, str(dest / "asn2wrs.py"), "-h"], capture_output=True, text=True,
                               cwd=dest)
        usage = (smoke.stdout + smoke.stderr).strip().splitlines()
        if not usage or "Traceback" in smoke.stderr:
            failures.append("asn2wrs.py -h did not run:\n" + smoke.stderr.strip())
        else:
            print(f"  smoke test: {usage[0]}")

    if failures:
        print("FAIL")
        print("\n".join(failures))
        return 1
    print("PASS: tools installed. Run: python scripts/OmniTap-Validate.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
