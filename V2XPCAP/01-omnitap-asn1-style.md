# OmniTap ASN.1 Source Style Guide

This guide defines the source style for the OmniTap ASN.1 module collection. It intentionally follows the visual character of SAE J2735 and OmniAir ASN.1 while emphasizing readability, generous whitespace, and documentation kept directly beside the ASN.1 that it describes.

## 1. Guiding Principle

**The ASN.1 source is both the machine-readable schema and the primary field-level data dictionary.**

Definitions SHALL include enough nearby documentation to understand their meaning without consulting a parallel data-dictionary document.

- Optimize ASN.1 source for human review, not compactness.
- Prefer clarity, alignment, and whitespace over minimizing line count.
- Keep identifiers, types, qualifiers, and comments visually tabular.
- Make the association between every definition and its documentation immediately obvious.
- Prefer the simplest ASN.1 that expresses the required semantics clearly.
- Avoid unrelated formatting changes in functional commits.

Architecture documents and README files may explain OmniTap, pcapng integration, workflows, examples, and design rationale. Field- and type-level semantics belong with the ASN.1 source.

## 2. Release Terminology

In this guide, a **release** means an approved and tagged OmniAir project release of the OmniTap ASN.1 module collection. It does not imply publication as an SDO standard.

Definitions may evolve freely before their first release. Once included in a release, they become compatibility-controlled as described below.

## 3. Files, Modules, and Top-Down Organization

Use exactly one ASN.1 module per `.asn` file.

The module collection SHALL read **from the outside inward**.

### File order

- Source filenames SHALL begin with a numeric ordering prefix.
- Lower numbers identify outer, top-level, or public modules.
- Progressively higher numbers identify subordinate or supporting modules.
- Numeric sub-prefixes such as `21-01`, `21-02`, etc. may be used for related sibling modules.
- The numeric prefix is not part of the ASN.1 module name.

Example:

```text
00-OmniTap-Objects.asn
10-OmniTap-Interface-Context.asn
21-01-OmniTap-RAT-LTE-V2X.asn
21-02-OmniTap-RAT-NR-V2X.asn
90-OmniTap-Common.asn
```

### Definition order within a module

Definitions SHALL normally appear in top-down order: the primary top-level/public definitions first, then the structures
they reference, and leaf scalar or constrained primitive definitions last. Where practical, list subordinate definitions in
the order in which they are first referenced.

The purpose is to let a reader understand a module from the outside inward without first reading implementation details.
The order of definitions has no effect on the UPER encoding, so reordering a module is a formatting-only change.

### Common module

`Common` is a dependency-management convenience, not a general-purpose data dictionary.

- Move a definition to `Common` only when it is actually shared by multiple functional modules and has the same semantics in each use.
- Do not move a type to `Common` merely because it is small, primitive, or might be reusable later.
- Keep function-specific definitions in their functional module.
- `Common` should remain near the bottom of the dependency graph.
- Functional modules may depend on `Common`; `Common` should not normally depend on functional modules.
- Avoid circular imports.
- Import only symbols actually used.

## 4. Simplicity and Inline Types

Unlike large reusable dictionaries such as SAE J2735, OmniTap does not require every data concept to have a separately named ASN.1 type.

Inline ASN.1 types and constraints are encouraged when introducing a separate named type would add indirection without meaningful reuse, semantics, or clarity.

```asn1
   retryCount          INTEGER (0..7),                    -- The number of retry attempts.
```

Introduce a separately named type when one or more of the following apply:

- The type is used in more than one location.
- It represents an independently meaningful domain concept.
- A name materially improves readability.
- The type has substantial constraints or semantics deserving separate documentation.

Do not create named wrapper types solely for stylistic consistency or anticipated future reuse.

## 5. Whitespace and Line Length

- Use **spaces only**. Tabs are prohibited.
- Use exactly **three spaces per indentation level**.
- Leave one blank line between individual elements, alternatives, named values, and top-level definitions.
- Use additional whitespace around documentation blocks so ownership is visually unambiguous.
- Do not use trailing whitespace.
- Use a **soft 130-character line-length target**.
- Alignment, established identifiers, and clear comments may exceed 130 characters when wrapping would reduce readability.
- The line-length target applies to ASN.1 source files only, not to Markdown documents.

## 6. ASN.1 Identifier Naming

For newly defined symbols:

- Modules and types: `UpperCamelCase`
- Components and values: `lowerCamelCase`
- Named numbers and enumeration items: `lowerCamelCase`
- Information object classes: uppercase, following established ASN.1 conventions for the applicable construct

Additional rules:

- Prefer descriptive names over abbreviations.
- Use established domain abbreviations when they are standard terminology.
- Use one name consistently for one concept.
- A component name used in more than one place SHALL have the same type each time. Wireshark's `asn2wrs` turns component
  names into display-filter names and warns when one name stands for different types, in one module or in several; the
  validation gate treats any warning as a failure. Where the types differ, give the components different names.
- Preserve names imported from external standards even when their style differs from this guide.
- ASN.1 identifiers SHALL NOT use underscores.
- Hyphens may be used where ASN.1 permits and where they improve or preserve established naming, but SHALL NOT be added gratuitously.

## 7. Module Declaration and Tagging

All modules SHALL specify `AUTOMATIC TAGS`.

```asn1
OmniTapObserver DEFINITIONS AUTOMATIC TAGS ::= BEGIN
```

Do not add explicit component tags merely as a stylistic convention. Use explicit tagging only when a specific ASN.1 or interoperability requirement requires it.

## 8. Definition Layout and Alignment

Keep `::=` on the same line as the definition name. Align `::=` within a local group of related definitions.

```asn1
ObserverId        ::= INTEGER (0..65535)

InterfaceId       ::= INTEGER (0..255)

CaptureSequence   ::= INTEGER (0..4294967295)
```

For constructed types, keep the opening `{` on the same line.

Within each local `SEQUENCE`, `SET`, `CHOICE`, `ENUMERATED`, import block, or definition group, align these columns where practical:

1. Identifier.
2. Type, constraint, or numeric assignment.
3. `OPTIONAL` or `DEFAULT` qualifier.
4. Inline comment.

Alignment is local, not repository-wide. An unusually long identifier SHALL NOT force unrelated definitions to change columns.

```asn1
Observer ::= SEQUENCE {

   observerId          INTEGER (0..65535),                 -- The unique observer identifier.

   timestamp           Timestamp,                          -- The time at which the packet was observed.

   position            Position3D                OPTIONAL, -- The observer position, when known.

   ...
}
```

## 9. Commas and Delimiters

Use traditional J2735-style comma placement.

- Place the comma immediately after the complete ASN.1 element.
- Place any inline comment after the comma.
- Do not put commas on separate lines.
- Do not add decorative trailing commas where ASN.1 syntax does not require them.

```asn1
   observerId          INTEGER (0..65535),                 -- The unique observer identifier.
```

## 10. Documentation and Comments

Documentation SHALL be treated as part of the ASN.1 specification, not as decoration.

### Documentation blocks

Every significant top-level definition or structure should have a descriptive block comment immediately before the definition. Separate the block from the preceding definition with whitespace.

A documentation block describes **the definition or element immediately following it**.

```asn1
-- Describes the entity responsible for observing captured packets.
--
-- The observer identifier is local to the pcapng capture. Position is optional
-- because a capture source is not required to provide geographic position.
--
Observer ::= SEQUENCE {
   ...
}
```

Detailed documentation for an individual element SHALL likewise appear immediately **before** that element rather than after it.

```asn1
PacketMetadata ::= SEQUENCE {

   packetId            INTEGER (0..MAX),                   -- The packet identifier.


   -- Identifies when the capture system observed this packet.
   --
   -- Unit: microseconds.
   -- Resolution: 1 microsecond.
   -- The reference epoch is defined by the enclosing capture context.
   --
   captureTime         INTEGER (0..MAX),                   -- The packet capture time.


   -- Present only when the capture interface supplies a signal-strength measurement.
   -- Absence does not imply a zero-valued measurement.
   --
   signalStrength      INTEGER (-200..100)       OPTIONAL, -- The received signal strength.

   ...
}
```

### Documentation content

Documentation should address all information that is applicable to the definition or element, including:

- Meaning and purpose.
- Units.
- Resolution or scaling.
- Reference point, epoch, coordinate system, or frame.
- Meaning of a `DEFAULT` when not obvious.
- Boundary, reserved, or special values when such values exist.
- External normative references when semantics originate elsewhere.
- Relationships or semantic constraints that ASN.1 syntax cannot express clearly.

Do not add meaningless boilerplate for categories that do not apply. In particular, OmniTap does not require sentinel values simply to satisfy a documentation template.

### Inline comments

Inline comments remain the preferred style for concise field identification.

```asn1
   packetCount         INTEGER (0..MAX),                   -- The number of captured packets.
```

- Align inline comments within the local structure.
- Write comments as complete sentences with normal punctuation.
- Use one space after `--`.
- Do not merely restate syntax already obvious from the ASN.1 definition.
- Use a preceding documentation block when the explanation is too detailed for a clear inline comment.

A useful rule is:

> **Block comments explain the concept; inline comments identify the element.**

## 11. Strong Section Dividers

Use strong section dividers for meaningful groups within larger modules.

```asn1
-- =============================================================================
-- Observer definitions.
-- =============================================================================
```

- Use this divider form consistently.
- Section headings use normal sentence punctuation.
- Do not create a divider for every individual definition; use one when it materially improves navigation.

## 12. `OPTIONAL` and `DEFAULT`

Place `OPTIONAL` and `DEFAULT` in a dedicated aligned qualifier column.

```asn1
   observerId          ObserverId,

   position            Position3D                OPTIONAL,

   packetFormat        PacketFormat              DEFAULT pcap,
```

Optionality and defaults SHALL remain visually prominent.

For an `OPTIONAL` component, document the meaning of absence whenever that meaning is significant or could reasonably be ambiguous. Do not assume that absence universally means `unknown`, `unavailable`, `not applicable`, or `not supported`.

## 13. `IMPORTS`

Use one imported symbol per line. Group symbols by source module, use a blank line between source modules, and place `FROM` on a visually distinct indented line.

```asn1
IMPORTS

   Position3D,
   Timestamp,
   VehicleId
      FROM OmniTapCommon

   Psid
      FROM Ieee1609Dot2BaseTypes
;
```

- Remove unused imports.
- Preserve externally defined module identifiers when required by the imported specification.
- Keep imports readable rather than compressing them into dense paragraphs.
- OmniTap is a self-contained, single-project module collection and does not require an external-dictionary versioning model such as `WITH SUCCESSORS`.

## 14. `ENUMERATED` and Named Numbers

Use one named value per line. Align names, numeric assignments, and comments in columns. Leave one blank line between values.

```asn1
PacketDisposition ::= ENUMERATED {

   unknown              (0),   -- The packet disposition is unknown.

   accepted             (1),   -- The packet was accepted.

   rejected             (2),   -- The packet was rejected.

   ...
}
```

For release-controlled assignments:

- Never renumber an existing value merely for neatness.
- Never reuse a retired value for different semantics.
- Preserve reserved values when required for compatibility.

## 15. Constraints, Units, and Special Values

Express machine-enforceable size, range, alphabet, and structural requirements directly in ASN.1 when practical.

```asn1
ObserverId        ::= INTEGER (0..65535)

VehicleId         ::= OCTET STRING (SIZE(8))

ObserverList      ::= SEQUENCE SIZE(1..64) OF Observer
```

Do not add an artificially narrow constraint merely because currently assigned values occupy a smaller range.

When applicable, use these terms consistently:

- `unknown`: A value or state exists conceptually but is not known.
- `unavailable`: The source cannot provide the value.
- `reserved`: An assignment is intentionally withheld from ordinary use.
- `doNotUse`: A previously released field or assignment is retained for compatibility but SHALL NOT be used by new implementations. For a component the name carries a number (`doNotUse1`, `doNotUse2`, ...); see section 17.

These concepts are not interchangeable. Their exact semantics SHALL be documented where they occur.

## 16. Extensibility

Every public `SEQUENCE`, `SET`, `CHOICE`, and `ENUMERATED` type **SHALL** include an extension marker (`...`). This applies to
named types and to inline constructed types alike.

- Write the marker explicitly in each type. Do not use module-wide `EXTENSIBILITY IMPLIED`.
- Place the marker last in the type. Anything added in a later release goes after it.
- Rationale: whether a type will need to grow cannot be predicted reliably, and adding or removing a marker after release
  changes the UPER encoding. The marker costs one bit for each encoded instance of the type.
- An extension marker denotes an intentional evolution point controlled by OmniTap. It is not a general-purpose invitation for
  private or vendor-specific additions; third-party content belongs in the extension containers defined for that purpose.
- Once released, adding, moving, or removing an extension marker is a compatibility-sensitive change.
- No exception is defined. A type that must be closed requires a design-review decision and a change to this section.

## 17. Released Definitions and Retirement

Compatibility requirements apply once a definition has been included in an approved, tagged OmniAir release.

Before the first release containing a definition, it may be corrected, reorganized, renamed, or removed as part of normal development. Do not preserve obsolete development-only fields as `doNotUse` merely because they previously existed in source control.

After release, changes SHALL preserve compatibility with previously released OmniTap pcapng data and, where applicable, ASN.1 source/import compatibility.

When a released field must be retired but its position and representation must remain for pcapng wire-format compatibility:

- Keep the field in its original position.
- Preserve its original ASN.1 type and encoding-relevant constraints.
- Rename it `doNotUse1`, `doNotUse2`, and so on. Number each retired field uniquely across the whole module collection and never
  reuse a number. A shared name such as `doNotUse` on fields of different types would make `asn2wrs` warn (see section 6).
- Document that the field is retained for compatibility and SHALL NOT be used by new implementations.
- Never assign a new semantic meaning to the retired field.

Likewise, released numeric assignments SHALL NOT be renumbered or reused for an unrelated purpose.

If a complete released type must remain for ASN.1 source/import compatibility, retain the type and clearly document its retired status and replacement rather than silently deleting or repurposing it.

## 18. Compatibility Review

Review changes independently for two kinds of compatibility.

### pcapng wire-format compatibility

**pcapng wire-format compatibility** means compatibility of the COER-encoded OmniTap data stored in pcapng.

Review changes to component ordering, constraints, extension markers, `CHOICE` alternatives, `ENUMERATED` assignments, `OPTIONAL` fields, `DEFAULT` values, and other encoding-relevant ASN.1 constructs for their effect on previously released pcapng data.

A formatting-only source change SHALL NOT intentionally alter the encoded representation.

### ASN.1 source/import compatibility

**ASN.1 source/import compatibility** means compatibility between ASN.1 modules and tools that compile, import, or otherwise consume published symbols.

Renaming or removing a released type, value, component, or imported symbol may break another ASN.1 module or tool even when the resulting COER/OER representation would otherwise be unchanged.

Source/import compatibility and pcapng wire-format compatibility SHALL therefore be reviewed separately.

## 19. Encoding

OmniTap uses **ASN.1 Canonical Octet Encoding Rules (COER, ITU-T X.696) exclusively** for producers (every COER encoding is also a valid Basic OER encoding for decoders).

This is a protocol/storage-format requirement, not a formatting preference. Constraints or structural changes that affect COER/OER encoding SHALL NOT be made as cosmetic style cleanup.

## 20. Validation

Every ASN.1 change SHALL be validated by Wireshark `asn2wrs` and **at least two independent ASN.1 compilers**.

Required validation SHALL include:

1. Wireshark `asn2wrs`.
2. One ASN.1 compiler.
3. A second independent ASN.1 compiler from a different implementation/toolchain.

Validation requirements:

- Validate the complete module collection after ASN.1 changes.
- Do not accept compilation errors.
- Investigate new warnings; resolve them or explicitly justify them.
- Use the same normative ASN.1 source across all validation toolchains.
- Do not maintain a separate hand-edited ASN.1 dialect solely for one compiler or Wireshark.
- Treat material differences in accepted syntax, constraints, imports, or generated models as interoperability issues requiring review.

## 21. Complete Style Example

```asn1
OmniTapObserver DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

   Position3D,
   Timestamp
      FROM OmniTapCommon
;


-- =============================================================================
-- Observer definitions.
-- =============================================================================


-- Describes the entity responsible for observing captured packets.
--
-- The observer identifier is local to the pcapng capture. Position is optional
-- because a capture source is not required to provide geographic position.
--
Observer ::= SEQUENCE {

   observerId          INTEGER (0..65535),                 -- The unique observer identifier.


   -- Identifies when the capture system observed the packet.
   --
   -- Unit: microseconds.
   -- Resolution: 1 microsecond.
   --
   timestamp           Timestamp,                          -- The packet observation time.


   -- Present only when the observer has valid geographic position information.
   -- Absence means that no observer position is provided for this observation.
   --
   position            Position3D                OPTIONAL, -- The observer position.

   ...
}

END
```
