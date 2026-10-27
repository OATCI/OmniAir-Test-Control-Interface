# OmniTap Block Architecture

## pcapng Block Flow
1. **IDB** (Defining interface details)
2. **Custom Block** (PEN 5656385) - Static Session Context (RRC state)
3. **Custom Block** (PEN 5656385) - Real-time Packet Metadata (RSSI, HARQ)
4. **EPB** - Pristine Raw Payload (with recordId for Lua correlation)
5. **Custom Block** (PEN 5656385) - Supplemental/Late Data
