# OmniAir OmniTap - High-Level Requirements

## 1. Project Vision & Governance
*   **Definitive Open Standard:** Establish OmniTap as the definitive, open-source standard for V2X packet capture.
*   **Open Governance:** Intended for open governance under OmniAir or SAE, maintaining a neutral technical namespace (`V2X-Capture-*`) independent of proprietary branding.
*   **Certification Ready:** Ensure the capture format includes all metadata required for OmniAir Certification plugfests and SAE J3161 compliance testing.

## 2. Integration & Ecosystem
*   **Standard Framework:** Built strictly on the standard IETF `pcapng` format; does not invent a new file format.
*   **Wireshark Compatibility:** Designed from day one to be easily upstreamed into the main Wireshark project.
*   **Lua-Friendly:** Metadata is injected via pcapng Custom Blocks (CB) using UPER encoding, allowing a portable Wireshark Lua script to easily parse and dissect the data without requiring a compiled C dissector.

## 3. Data Representation & Semantics
*   **Clean-Slate Architecture:** Drops legacy baggage and proprietary wrappers.
*   **Latest-Wins State:** Packet annotations utilize a "latest-wins" or single-state representation. This drastically simplifies dissector behavior and ensures better compatibility with finalized test artifacts.
*   **Absence = No Assertion:** An absent optional field means no assertion (unknown, unavailable, not exposed). 
*   **No Sentinel Values:** Avoids legacy J2735 numeric sentinel values (e.g., using `8191` to mean unavailable). If a value is unknown, the field is simply omitted.
*   **Physical Semantics:** Numerical ranges and precision for physical semantics (e.g., coordinates, speeds, timing) should mirror SAE J2735 standards for consistency, but without inheriting its types or sentinels.

## 4. ASN.1 Structure
*   **RAT Partitioning:** Modules are strictly partitioned by Radio Access Technology (RAT) into separate files (e.g., NR-V2X, LTE-V2X, DSRC, ARIB-T760) for modularity.
*   **Extensibility:** Must support opaque regional and manufacturer-specific extensions in a bounded, optional manner.
