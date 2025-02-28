![Screenshot of Wireshark demonstrating a reassembled PDU](screenshot.png?raw=true)

# Example Wireshark Dissector with UDP Reassembly

This repository implements a Lua dissector for Wireshark that demonstrates how to handle UDP reassembly.

Our toy protocol's data unit (PDU) is a simple length-prefixed string, known as a Pascal string. These PDUs might be fragmented across multiple packets, concatenated within a single packet, or a combination of both. The dissector can handle these scenarios.

For other protocols, the developer should only need to reimplement `read_complete_pdu()`.

This code was last tested against Wireshark version 4.4.5.
