#!/usr/bin/env python3
"""Repository checks for OmniTap ASN.1 sources.

Usage:
    python scripts/OmniTap-Validate.py [--oid-root ARCS] [--no-compile] [--no-asn2wrs] [--asn2wrs PATH] [PATH ...]

PATH may be an ASN.1 file or a directory. Without PATH, every *.asn file in the repository root (or current working
directory) is checked.

Checks:
1. Policy: line length (a hard limit here, although the style guide calls 130 a soft target), tab characters, trailing
   whitespace, filename pattern, an extension marker '...' in every SEQUENCE, SET, CHOICE and ENUMERATED including inline
   ones, numbered doNotUse1, doNotUse2, ... for retired components (each unique across the collection), prohibited names.
2. Module OID: each module header OID is the root, then the two-digit filename prefix arc(s), then the major and minor
   version arcs. Example: 21-03-OmniTap-RAT-ETSI-ITSG5.asn -> { <root> 21 3 <major> <minor> }.
3. Uniqueness: no two files define the same module name or module OID.
4. IMPORTS: every FROM module reference names a module in the checked set, every imported symbol is defined in
   that module and used by the importing module, and any OID on an IMPORTS line equals the source module's header OID.
5. Joint compilation of all modules with asn1tools (OER/COER), which also resolves cross-module type references. The
   parsed model is also used to check identifier case: UpperCamelCase types, lowerCamelCase components and enumeration
   values, no underscores or hyphens.
6. Wireshark asn2wrs generates an OER dissector from all modules, in a temporary directory, with no errors and no
   warnings. This is the asn2wrs part of the release gate; the generated C is discarded.

Run scripts/OmniTap-Setup.py once first to install asn1tools and fetch Wireshark asn2wrs.
These checks do not replace the release gate's two independent strict ASN.1 compilers.
"""
from pathlib import Path
import argparse
import re
import sys

# Never crash while reporting: Windows consoles (cp1252) cannot print every Unicode character.
sys.stdout.reconfigure(errors="backslashreplace")
# utf-8-sig accepts files with or without a UTF-8 byte-order mark (Windows PowerShell 5.1 writes one).
SOURCE_ENCODING = "utf-8-sig"
MAX_LINE_LENGTH = 130
# PEN 32473 is the RFC 5612 documentation PEN; arc 1 under it is OmniTap. Replace when the production PEN is assigned.
DEFAULT_OID_ROOT = "1 3 6 1 4 1 32473 1"
VERSION_ARC_COUNT = 2  # major, minor
ROOT = Path(__file__).resolve().parent.parent

FILENAME_PATTERN = re.compile(r"^(?P<prefix>\d{2}(?:-\d{2})*)-OmniTap-[A-Za-z0-9-]+\.asn$")
MODULE_HEADER = re.compile(r"(?P<name>\b[A-Z][A-Za-z0-9-]*)\s*\{(?P<oid>[^}]*)\}\s*DEFINITIONS\b")
ASSIGNMENT = re.compile(r"^\s*(?P<name>[A-Za-z][A-Za-z0-9-]*)\b[^\n]*?::=", re.M)
CONSTRUCTED_TYPE = re.compile(r"\b(?P<kind>SEQUENCE|SET|CHOICE|ENUMERATED)\s*\{")
RETIRED_COMPONENT = re.compile(r"^\s*(?P<name>doNotUse\w*)\s+(?=[A-Z])", re.M)
RETIRED_NAME = re.compile(r"^doNotUse[1-9][0-9]*$")
UPPER_CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
LOWER_CAMEL = re.compile(r"^[a-z][A-Za-z0-9]*$")
IMPORTS_BLOCK = re.compile(r"\bIMPORTS\b(?P<body>.*?);", re.S)
FROM_CLAUSE = re.compile(r"(?P<symbols>.*?)\bFROM\s+(?P<module>[A-Z][A-Za-z0-9-]*)\s*(?:\{(?P<oid>[^}]*)\})?", re.S)
PROHIBITED = [
    (re.compile(r"\bValueSource\b"), "ValueSource is prohibited"),
    (re.compile(r"\bPrivateExtension\b"), "use ThirdPartyExtension terminology"),
    (re.compile(r"T760"), "'T760' is not a real standard; use ARIB STD-T109 / aribT109"),
    (re.compile(r"\b(?:itsConnect|ItsConnectMetadata|dsrc|DsrcMetadata)\b"), "superseded RAT identifier"),
    (re.compile(r"\bThirdPartyExtensions\b"), "renamed: use OptionalExtensions (field optionalExtensions)"),
    (re.compile(r"\b(?:GeodeticDatum|GeodeticLocation|otherDatumId)\b"),
     "renamed: use CoordinateReferenceSystem / GeographicPosition / otherCoordinateSystemId"),
    (re.compile(r"\b(?:ReceiveObservation|TransmitObservation|ReceiveRadioObservation|TransmitRadioObservation)\b"),
     "replaced by ObserverLocation and RadioObservation"),
    (re.compile(r"\b(?:targetInterfaceId|PcapngInterfaceId)\b"), "removed: interfaces are identified by sessionTag and interfaceName"),
]


def strip_comments(text):
    """Blank out ASN.1 comments ('--' to the next '--' or end of line, and /* */), keeping line numbers."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)
    return "\n".join(re.sub(r"--.*?(?:--|$)", " ", line) for line in text.splitlines())


def parse_oid(oid_text):
    """Return OID arcs as a tuple of ints. Accepts 'n' and 'name(n)'; a bare name cannot be checked and is an error."""
    arcs = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9-]*\s*\(\s*\d+\s*\)|\d+|[A-Za-z][A-Za-z0-9-]*", oid_text):
        # In 'name(n)' the arc is the number in parentheses; the name itself may contain digits (e.g. lteV2x(1)).
        number = re.search(r"\(\s*(\d+)\s*\)", token) or re.fullmatch(r"(\d+)", token)
        if not number:
            raise ValueError(f"OID component '{token}' has no number")
        arcs.append(int(number.group(1)))
    return tuple(arcs)


def show(arcs):
    return "{ " + " ".join(map(str, arcs)) + " }"


def matching_brace(text, open_index):
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def has_extension_marker(inner):
    """True when '...' stands directly inside a constructed type, not in a nested type or in a constraint."""
    depth = 0
    for index, char in enumerate(inner):
        if char in "{(":
            depth += 1
        elif char in "})":
            depth -= 1
        elif depth == 0 and inner.startswith("...", index):
            return True
    return False


def check_identifiers(parsed, modules, errors):
    """UpperCamelCase types; lowerCamelCase components and enumeration values (style guide, section 6)."""
    def walk(definition, path, file_name):
        for member in definition.get("members") or []:
            if isinstance(member, dict) and "name" in member:
                if not LOWER_CAMEL.match(member["name"]):
                    errors.append(f"{file_name}: component {path}.{member['name']} is not lowerCamelCase")
                walk(member, f"{path}.{member['name']}", file_name)
        for value in definition.get("values") or []:
            if value not in (None, "...") and not LOWER_CAMEL.match(value[0]):
                errors.append(f"{file_name}: enumeration value {path}.{value[0]} is not lowerCamelCase")
        if isinstance(definition.get("element"), dict):
            walk(definition["element"], path, file_name)

    for module_name, module in parsed.items():
        file_name = modules.get(module_name, {}).get("file", module_name)
        for type_name, definition in module["types"].items():
            if not UPPER_CAMEL.match(type_name):
                errors.append(f"{file_name}: type {type_name} is not UpperCamelCase (no hyphens or underscores)")
            walk(definition, type_name, file_name)


def collect_paths(arguments):
    if not arguments:
        for candidate in (Path.cwd() / "asn", Path.cwd(), ROOT / "asn", ROOT):
            if candidate.is_dir():
                found = sorted(candidate.glob("*.asn"))
                if found:
                    return found
        return []
    paths = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            found = sorted(path.glob("*.asn"))
            if not found and (path / "asn").is_dir():
                found = sorted((path / "asn").glob("*.asn"))
            paths.extend(found)
        elif path.is_file():
            paths.append(path)
        else:
            raise SystemExit(f"ERROR: {argument}: no such file or directory")
    return paths


def run_asn2wrs(script, asn_files, errors):
    """Generate the Wireshark OER dissector in a temporary directory. Any error or warning is a failure."""
    if not script.is_file():
        errors.append(f"asn2wrs not found at {script}; run: python scripts/OmniTap-Setup.py")
        return "not run"
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory(prefix="omnitap-asn2wrs-") as work:
        # asn2wrs writes its output to the current directory, so run it inside the temporary directory.
        cnf_path = Path(work) / "omnitap.cnf"
        cnf_path.write_text("#.OPT\nOER\n#.END\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(script.resolve()), "-e", "-c", str(cnf_path), "-p", "omnitap",
             *[str(p.resolve()) for p in asn_files]],
            cwd=work, capture_output=True, text=True, encoding="utf-8", errors="replace")
        produced = sorted(Path(work).glob("packet-omnitap*"))
        diagnostics = [line for line in result.stderr.splitlines() if line.strip()]
        warnings_seen = [line for line in diagnostics if "Warning" in line or "Error" in line or "Traceback" in line]
        if result.returncode != 0:
            errors.append(f"asn2wrs exited with {result.returncode}:\n  " + "\n  ".join(diagnostics[-15:]))
        elif not produced:
            errors.append("asn2wrs produced no dissector files")
        if warnings_seen:
            errors.append(f"asn2wrs issued {len(warnings_seen)} warning(s):")
            # A same-field-name warning is followed on stderr by the field name and one line per conflicting use:
            # ' <field>[_NN] <type> <Parent>/<field>'. Report each field with all of its uses.
            for field, uses in re.findall(r"^(\w+)\n((?: \S+\s+\S+\s+\S+\n?)+)", result.stderr, re.M):
                paths = [f"{use.split()[2]} ({use.split()[1]})" for use in uses.strip("\n").splitlines()]
                errors.append(f"  asn2wrs: field name '{field}' has different types in: {'; '.join(paths)}")
            others = [line for line in warnings_seen if "same field names" not in line]
            errors.extend(f"  asn2wrs: {line.strip()}" for line in others)
        return f"OK ({len(produced)} files)" if result.returncode == 0 and produced and not warnings_seen else "FAILED"


def main():
    parser = argparse.ArgumentParser(description="OmniTap ASN.1 repository checks.")
    parser.add_argument("paths", nargs="*", help="ASN.1 files or directories (default: *.asn in repository root)")
    parser.add_argument("--oid-root", default=DEFAULT_OID_ROOT,
                        help=f"module OID root arcs before the filename arcs (default: '{DEFAULT_OID_ROOT}')")
    parser.add_argument("--no-compile", action="store_true", help="skip the asn1tools joint compilation")
    parser.add_argument("--no-asn2wrs", action="store_true", help="skip the Wireshark asn2wrs generation check")
    parser.add_argument("--asn2wrs", default=str(ROOT / "tools" / "wireshark" / "asn2wrs.py"),
                        help="path to asn2wrs.py (default: tools/wireshark/asn2wrs.py, fetched by scripts/OmniTap-Setup.py)")
    arguments = parser.parse_args()

    oid_root = parse_oid(arguments.oid_root)
    asn_files = collect_paths(arguments.paths)
    errors = []
    if not asn_files:
        print("FAIL\nNo ASN.1 files found.")
        return 1

    modules = {}    # module name -> {"file": str, "oid": tuple, "symbols": set}
    oid_owner = {}  # module OID -> file name
    imports = []    # (file name, line number, module reference, OID text or None, [symbols], definition text)
    retired = {}    # retired component name -> [file:line, ...]

    for path in asn_files:
        name = path.name
        raw = path.read_text(encoding=SOURCE_ENCODING)
        for line_no, line in enumerate(raw.splitlines(), 1):
            if len(line) > MAX_LINE_LENGTH:
                errors.append(f"{name}:{line_no}: line is {len(line)} characters; maximum is {MAX_LINE_LENGTH}")
            if "\t" in line:
                errors.append(f"{name}:{line_no}: tab character; use spaces")
            if line != line.rstrip():
                errors.append(f"{name}:{line_no}: trailing whitespace")
        for pattern, message in PROHIBITED:
            for match in pattern.finditer(raw):
                errors.append(f"{name}:{raw.count(chr(10), 0, match.start()) + 1}: {message}")

        text = strip_comments(raw)
        filename = FILENAME_PATTERN.match(name)
        if not filename:
            errors.append(f"{name}: filename must match NN[-NN...]-OmniTap-<Name>.asn")

        header = MODULE_HEADER.search(text)
        if not header:
            errors.append(f"{name}: no module header '<ModuleName> {{ <oid> }} DEFINITIONS' found")
            continue
        module_name = header.group("name")
        try:
            module_oid = parse_oid(header.group("oid"))
        except ValueError as exc:
            errors.append(f"{name}: module OID: {exc}")
            module_oid = None

        if module_oid is not None and filename:
            file_arcs = tuple(int(part) for part in filename.group("prefix").split("-"))
            expected_prefix = oid_root + file_arcs
            actual_prefix = module_oid[:len(expected_prefix)]
            versions = module_oid[len(expected_prefix):]
            if actual_prefix != expected_prefix:
                errors.append(f"{name}: module OID {show(module_oid)} does not match root and filename prefix "
                              f"{show(expected_prefix)} + major + minor")
            elif len(versions) != VERSION_ARC_COUNT:
                errors.append(f"{name}: module OID {show(module_oid)} must end with exactly major and minor "
                              f"version arcs after {show(expected_prefix)}")
        if module_oid is not None:
            if module_oid in oid_owner:
                errors.append(f"{name}: module OID {show(module_oid)} duplicates {oid_owner[module_oid]}")
            oid_owner[module_oid] = name
        if module_name in modules:
            errors.append(f"{name}: module name {module_name} duplicates {modules[module_name]['file']}")

        body_start = header.end()
        body = text[body_start:]
        modules[module_name] = {"file": name, "oid": module_oid,
                                "symbols": {m.group("name") for m in ASSIGNMENT.finditer(body)}}

        lines = text.splitlines()
        for match in CONSTRUCTED_TYPE.finditer(text):
            close = matching_brace(text, match.end() - 1)
            if close < 0 or not has_extension_marker(text[match.end():close]):
                line_no = text.count("\n", 0, match.start()) + 1
                errors.append(f"{name}:{line_no}: {match.group('kind')} lacks extension marker '...': "
                              f"{lines[line_no - 1].strip()[:70]}")

        for match in RETIRED_COMPONENT.finditer(text):
            line_no = text.count("\n", 0, match.start("name")) + 1
            if not RETIRED_NAME.match(match.group("name")):
                errors.append(f"{name}:{line_no}: retired component '{match.group('name')}' must be numbered "
                              f"(doNotUse1, doNotUse2, ...)")
            retired.setdefault(match.group("name"), []).append(f"{name}:{line_no}")

        block = IMPORTS_BLOCK.search(body)
        if block:
            body_offset = body_start + block.start("body")
            definition_text = body[:block.start()] + body[block.end():]
            for clause in FROM_CLAUSE.finditer(block.group("body")):
                line_no = text.count("\n", 0, body_offset + clause.start("module")) + 1
                symbols = [s.strip() for s in clause.group("symbols").split(",") if s.strip()]
                imports.append((name, line_no, clause.group("module"), clause.group("oid"), symbols, definition_text))

    for file_name, line_no, reference, oid_text, symbols, definition_text in imports:
        target = modules.get(reference)
        if target is None:
            errors.append(f"{file_name}:{line_no}: IMPORTS FROM {reference}: no checked file defines this module")
            continue
        if oid_text is not None:
            try:
                written = parse_oid(oid_text)
            except ValueError as exc:
                errors.append(f"{file_name}:{line_no}: IMPORTS FROM {reference}: OID: {exc}")
            else:
                if written != target["oid"]:
                    errors.append(f"{file_name}:{line_no}: IMPORTS FROM {reference} {show(written)} does not match "
                                  f"{target['file']} header OID {show(target['oid'])}")
        for symbol in symbols:
            if symbol not in target["symbols"]:
                errors.append(f"{file_name}:{line_no}: imports {symbol} FROM {reference}, "
                              f"but {target['file']} does not define it")
            elif not re.search(rf"(?<![A-Za-z0-9-]){re.escape(symbol)}(?![A-Za-z0-9-])", definition_text):
                errors.append(f"{file_name}:{line_no}: imports {symbol} FROM {reference}, but does not use it")

    for token, places in retired.items():
        if len(places) > 1:
            errors.append(f"retired component {token} is used {len(places)} times ({', '.join(places)}); "
                          f"number each retired component uniquely across the collection")

    compiled = "skipped"
    if not arguments.no_compile:
        try:
            import asn1tools
        except ImportError:
            errors.append("asn1tools is not installed; run: python scripts/OmniTap-Setup.py")
        else:
            try:
                spec = asn1tools.compile_files([str(p) for p in asn_files], "oer", encoding=SOURCE_ENCODING)
                compiled = f"OK ({len(spec.types)} types)"
                check_identifiers(asn1tools.parse_files([str(p) for p in asn_files], encoding=SOURCE_ENCODING), modules, errors)
            except Exception as exc:  # asn1tools raises ParseError, CompileError, and others
                errors.append(f"asn1tools OER compile failed: {type(exc).__name__}: {exc}")

    generated = "skipped"
    if not arguments.no_asn2wrs:
        generated = run_asn2wrs(Path(arguments.asn2wrs), asn_files, errors)

    if errors:
        print("FAIL")
        print("\n".join(errors))
        return 1
    print(f"PASS: {len(asn_files)} ASN.1 modules; policy, module-OID, uniqueness, and IMPORTS checks passed; "
          f"asn1tools OER compile {compiled}; asn2wrs {generated}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

